# -*- coding: utf-8 -*-
#
# Copyright 2016-2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>

import uuid
from contextlib import contextmanager
from itertools import izip
from threading import Lock
import psycopg2
from sqlalchemy import and_, create_engine, exc, func, or_
from sqlalchemy.orm import sessionmaker, scoped_session
from .models import ACL, ACLTemplate, Policy, ACLTemplatePolicy, Token as TokenModel
from .token import Token
from .exceptions import (DuplicatePolicyException, DuplicateTemplateException,
                         InvalidLimitException, InvalidOffsetException,
                         InvalidSortColumnException,
                         InvalidSortDirectionException, UnknownPolicyException,
                         UnknownTokenException)


class Storage(object):

    def __init__(self, policy_crud, token_crud):
        self._policy_crud = policy_crud
        self._token_crud = token_crud

    def add_policy_acl_template(self, policy_uuid, acl_template):
        self._policy_crud.associate_policy_template(policy_uuid, acl_template)

    def count_policies(self, term):
        search_pattern = self._prepare_search_pattern(term)
        return self._policy_crud.count(search_pattern)

    def delete_policy_acl_template(self, policy_uuid, acl_template):
        self._policy_crud.dissociate_policy_template(policy_uuid, acl_template)

    def get_policy(self, policy_uuid):
        if self._is_uuid(policy_uuid):
            for policy in self._policy_crud.get(policy_uuid, 'name', 'asc', None, None):
                return policy
        raise UnknownPolicyException()

    def get_policy_by_name(self, policy_name):
        for policy in self._policy_crud.get(policy_name, 'name', 'asc', None, None):
            if policy['name'] == policy_name:
                return policy
        raise UnknownPolicyException()

    def get_token(self, token_id):
        token_data = self._token_crud.get(token_id)
        if not token_data:
            raise UnknownTokenException()

        id_ = token_data.pop('uuid')
        return Token(id_, **token_data)

    def create_policy(self, name, description, acl_templates):
        return self._policy_crud.create(name, description, acl_templates)

    def create_token(self, token_payload):
        token_data = token_payload.__dict__
        token_uuid = self._token_crud.create(token_data)
        return Token(token_uuid, **token_data)

    def delete_policy(self, policy_uuid):
        self._policy_crud.delete(policy_uuid)

    def list_policies(self, term, order, direction, limit, offset):
        search_pattern = self._prepare_search_pattern(term)
        return self._policy_crud.get(search_pattern, order, direction, limit, offset)

    def update_policy(self, policy_uuid, name, description, acl_templates):
        self._policy_crud.update(policy_uuid, name, description, acl_templates)

    def remove_token(self, token_id):
        self._token_crud.delete(token_id)

    @staticmethod
    def _prepare_search_pattern(term):
        if not term:
            return '%'

        words = [w for w in term.split(' ') if w]
        return '%{}%'.format('%'.join(words))

    @staticmethod
    def _is_uuid(value):
        try:
            uuid.UUID(value)
            return True
        except (ValueError, TypeError):
            return False

    @classmethod
    def from_config(cls, config):
        factory = _ConnectionFactory(config['db_uri'])
        policy_crud = _PolicyCRUD(factory)
        token_crud = _TokenCRUD(factory)
        return cls(policy_crud, token_crud)


class _CRUD(object):

    _UNIQUE_CONSTRAINT_CODE = '23505'

    def __init__(self, connection_factory):
        self._factory = connection_factory

    def connection(self):
        return self._factory.connection()

    @contextmanager
    def new_session(self):
        session = self._factory.get_session()
        try:
            yield session
            session.commit()
        except (exc.OperationalError, exc.SQLAlchemyError):
            session.rollback()
            raise

    @staticmethod
    def row_to_dict(columns, row):
        return dict(izip(columns, row))


class _PolicyCRUD(_CRUD):

    _SELECT_POLICY_QRY = """\
SELECT auth_policy.uuid,
       auth_policy.name,
       auth_policy.description,
       array_agg(auth_acl_template.template) AS acl_templates
FROM auth_policy
LEFT JOIN auth_policy_template ON auth_policy.uuid = auth_policy_template.policy_uuid
LEFT JOIN auth_acl_template ON auth_policy_template.template_id = auth_acl_template.id
WHERE auth_policy.uuid ILIKE %s
      OR auth_policy.name ILIKE %s
      OR auth_policy.description ILIKE %s
GROUP BY auth_policy.uuid, auth_policy.name, auth_policy.description
ORDER BY auth_policy.{} {}
LIMIT {} OFFSET {}
"""
    _RETURNED_COLUMNS = ['uuid', 'name', 'description', 'acl_templates']

    def associate_policy_template(self, policy_uuid, acl_template):
        with self.new_session() as s:
            if not self._policy_exists(s, policy_uuid):
                raise UnknownPolicyException()

            self._associate_acl_templates(s, policy_uuid, [acl_template])
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    s.rollback()
                    raise DuplicateTemplateException(acl_template)
                raise

    def dissociate_policy_template(self, policy_uuid, acl_template):
        with self.new_session() as s:
            if not self._policy_exists(s, policy_uuid):
                raise UnknownPolicyException()

            filter_ = ACLTemplate.template == acl_template
            templ_ids = [t.id_ for t in s.query(ACLTemplate.id_).filter(filter_).all()]

            for templ_id in templ_ids:
                filter_ = and_(
                    ACLTemplatePolicy.policy_uuid == policy_uuid,
                    ACLTemplatePolicy.template_id == templ_id,
                )
                s.query(ACLTemplatePolicy).filter(filter_).delete(synchronize_session=False)

    def count(self, search_pattern):
        filter_ = or_(
            Policy.uuid.ilike(search_pattern),
            Policy.name.ilike(search_pattern),
            Policy.description.ilike(search_pattern),
        )
        with self.new_session() as s:
            return s.query(func.count(Policy.uuid)).filter(filter_).scalar()

    def create(self, name, description, acl_templates):
        policy = Policy(name=name, description=description)
        with self.new_session() as s:
            s.add(policy)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    s.rollback()
                    raise DuplicatePolicyException(name)
                raise
            self._associate_acl_templates(s, policy.uuid, acl_templates)
        return policy.uuid

    def delete(self, policy_uuid):
        filter_ = Policy.uuid == policy_uuid

        with self.new_session() as s:
            nb_deleted = s.query(Policy).filter(filter_).delete(synchronize_session=False)

        if not nb_deleted:
            raise UnknownPolicyException()

    def get(self, search_pattern, order, direction, limit, offset):
        if order not in ['name', 'description', 'uuid']:
            raise InvalidSortColumnException(order)

        if direction not in ['asc', 'desc']:
            raise InvalidSortDirectionException(direction)

        offset = self._check_valid_limit_or_offset(offset, 0, InvalidOffsetException)
        limit = self._check_valid_limit_or_offset(limit, 'ALL', InvalidLimitException)

        query = self._SELECT_POLICY_QRY.format(
            order, direction.upper(), limit, offset)

        with self.connection().cursor() as curs:
            curs.execute(query, (search_pattern, search_pattern, search_pattern))
            rows = curs.fetchall()

        policies = []
        for row in rows:
            policy = self.row_to_dict(self._RETURNED_COLUMNS, row)

            # The array_agg function returns [None] if there no acl_template
            if policy['acl_templates'] == [None]:
                policy['acl_templates'] = []

            policies.append(policy)

        return policies

    def update(self, policy_uuid, name, description, acl_templates):
        with self.new_session() as s:
            filter_ = Policy.uuid == policy_uuid
            body = {'name': name, 'description': description}
            affected_rows = s.query(Policy).filter(filter_).update(body)
            if not affected_rows:
                raise UnknownPolicyException()

            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    s.rollback()
                    raise DuplicatePolicyException(name)
                raise

            self._dissociate_all_acl_templates(s, policy_uuid)
            self._associate_acl_templates(s, policy_uuid, acl_templates)

    def _associate_acl_templates(self, session, policy_uuid, acl_templates):
        ids = self._create_or_find_acl_templates(session, acl_templates)
        template_policies = [ACLTemplatePolicy(policy_uuid=policy_uuid, template_id=id_) for id_ in ids]
        session.add_all(template_policies)

    def _check_valid_limit_or_offset(self, value, default, exc):
        if value is True or value is False:
            raise exc(value)

        if value is None:
            return default

        try:
            value = int(value)
        except ValueError:
            raise exc(value)

        if value < 0:
            raise exc(value)

        return value

    def _create_or_find_acl_templates(self, s, acl_templates):
        if not acl_templates:
            return []

        tpl = s.query(ACLTemplate).filter(ACLTemplate.template.in_(acl_templates)).all()
        existing = {t.template: t.id_ for t in tpl}
        for template in acl_templates:
            if template in existing:
                continue
            id_ = self._insert_acl_template(s, template)
            existing[template] = id_
        return existing.values()

    def _dissociate_all_acl_templates(self, s, policy_uuid):
        filter_ = ACLTemplatePolicy.policy_uuid == policy_uuid
        s.query(ACLTemplatePolicy).filter(filter_).delete(synchronize_session=False)

    def _insert_acl_template(self, s, template):
        tpl = ACLTemplate(template=template)
        s.add(tpl)
        s.commit()
        return tpl.id_

    def _policy_exists(self, s, policy_uuid):
        policy_count = s.query(func.count(Policy.uuid)).filter(Policy.uuid == policy_uuid).scalar()
        return policy_count != 0


class _TokenCRUD(_CRUD):

    def create(self, body):
        token = TokenModel(
            auth_id=body['auth_id'],
            user_uuid=body['xivo_user_uuid'],
            xivo_uuid=body['xivo_uuid'],
            issued_t=int(body['issued_t']),
            expire_t=int(body['expire_t']),
        )
        with self.new_session() as s:
            s.add(token)
            s.commit()
            acls = [ACL(token_uuid=token.uuid, value=acl) for acl in body.get('acls') or []]
            s.add_all(acls)
        return token.uuid

    def get(self, token_uuid):
        with self.new_session() as s:
            token = s.query(TokenModel).filter(TokenModel.uuid == token_uuid).first()
            if not token:
                raise UnknownTokenException()

            filter_ = ACL.token_uuid == token.uuid
            acls = [acl.value for acl in s.query(ACL.value).filter(filter_).all()]

        return {
            'uuid': token.uuid,
            'auth_id': token.auth_id,
            'xivo_user_uuid': token.user_uuid,
            'xivo_uuid': token.xivo_uuid,
            'issued_t': token.issued_t,
            'expire_t': token.expire_t,
            'acls': acls,
        }

    def delete(self, token_uuid):
        filter_ = TokenModel.uuid == token_uuid

        with self.new_session() as s:
            s.query(TokenModel).filter(filter_).delete(synchronize_session=False)


class _ConnectionFactory(object):

    def __init__(self, db_uri):
        self._db_uri = db_uri
        self._connection_lock = Lock()
        self._conn = self._new_connection()
        self._Session = scoped_session(sessionmaker())
        engine = create_engine(db_uri)
        self._Session.configure(bind=engine)

    def _new_connection(self):
        conn = psycopg2.connect(self._db_uri)
        conn.autocommit = True
        return conn

    def connection(self):
        with self._connection_lock:
            if self._conn.closed:
                self._conn = self._new_connection()

            try:
                with self._conn.cursor() as curs:
                    curs.execute('SELECT 1;')
            except psycopg2.OperationalError:
                self._conn = self._new_connection()

            return self._conn

    def get_session(self):
        return self._Session()
