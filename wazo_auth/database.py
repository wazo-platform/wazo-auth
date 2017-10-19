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
import time
import logging
from contextlib import contextmanager
from sqlalchemy import and_, create_engine, exc, func, or_, text
from sqlalchemy.orm import sessionmaker, scoped_session
from .models import (
    ACL,
    ACLTemplate,
    ACLTemplatePolicy,
    Email,
    Policy,
    Token as TokenModel,
    User,
)
from .token import Token
from .exceptions import (
    ConflictException,
    DuplicatePolicyException,
    DuplicateTemplateException,
    InvalidLimitException,
    InvalidOffsetException,
    InvalidSortColumnException,
    InvalidSortDirectionException,
    UnknownPolicyException,
    UnknownTokenException,
    UnknownUserException,
)

logger = logging.getLogger(__name__)


class Storage(object):

    def __init__(self, policy_crud, token_crud, user_crud):
        self._policy_crud = policy_crud
        self._token_crud = token_crud
        self._user_crud = user_crud

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

    def user_count(self, **kwargs):
        term = kwargs.get('search')
        if term:
            kwargs['search'] = self._prepare_search_pattern(term)
        return self._user_crud.count(**kwargs)

    def user_delete(self, user_uuid):
        self._user_crud.delete(user_uuid)

    def user_create(self, username, email_address, hash_, salt):
        user_uuid = self._user_crud.create(username, email_address, hash_, salt)
        return dict(
            uuid=user_uuid,
            username=username,
            email_address=email_address,
        )

    def user_list(self, **kwargs):
        term = kwargs.get('search')
        if term:
            kwargs['search'] = self._prepare_search_pattern(term)
        return self._user_crud.list_(**kwargs)

    def remove_token(self, token_id):
        self._token_crud.delete(token_id)

    def remove_expired_tokens(self):
        self._token_crud.delete_expired_tokens()

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
        policy_crud = _PolicyCRUD(config['db_uri'])
        token_crud = _TokenCRUD(config['db_uri'])
        user_crud = _UserCRUD(config['db_uri'])
        return cls(policy_crud, token_crud, user_crud)


class _CRUD(object):

    _UNIQUE_CONSTRAINT_CODE = '23505'

    def __init__(self, db_uri):
        self._Session = scoped_session(sessionmaker())
        engine = create_engine(db_uri)
        self._Session.configure(bind=engine)

    @contextmanager
    def new_session(self):
        session = self._Session()
        try:
            yield session
            session.commit()
        except:
            session.rollback()
            raise
        finally:
            self._Session.remove()


class _PolicyCRUD(_CRUD):

    def __init__(self, *args, **kwargs):
        super(_PolicyCRUD, self).__init__(*args, **kwargs)
        column_map = dict(
            name=Policy.name,
            description=Policy.description,
            uuid=Policy.uuid,
        )
        self._paginator = QueryPaginator(column_map)

    def associate_policy_template(self, policy_uuid, acl_template):
        with self.new_session() as s:
            if not self._policy_exists(s, policy_uuid):
                raise UnknownPolicyException()

            self._associate_acl_templates(s, policy_uuid, [acl_template])
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
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
                s.query(ACLTemplatePolicy).filter(filter_).delete()

    def _new_search_filter(self, search_pattern):
        return or_(
            Policy.uuid.ilike(search_pattern),
            Policy.name.ilike(search_pattern),
            Policy.description.ilike(search_pattern),
        )

    def count(self, search_pattern):
        filter_ = self._new_search_filter(search_pattern)
        with self.new_session() as s:
            return s.query(Policy).filter(filter_).count()

    def create(self, name, description, acl_templates):
        policy = Policy(name=name, description=description)
        with self.new_session() as s:
            s.add(policy)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    raise DuplicatePolicyException(name)
                raise
            self._associate_acl_templates(s, policy.uuid, acl_templates)
            return policy.uuid

    def delete(self, policy_uuid):
        filter_ = Policy.uuid == policy_uuid

        with self.new_session() as s:
            nb_deleted = s.query(Policy).filter(filter_).delete()

        if not nb_deleted:
            raise UnknownPolicyException()

    def get(self, search_pattern, **kwargs):
        filter_ = self._new_search_filter(search_pattern)
        with self.new_session() as s:
            query = s.query(
                Policy.uuid,
                Policy.name,
                Policy.description,
                func.array_agg(ACLTemplate.template).label('acl_templates'),
            ).outerjoin(
                ACLTemplatePolicy,
            ).outerjoin(
                ACLTemplate,
            ).filter(
                filter_,
            ).group_by(
                Policy.uuid,
                Policy.name,
                Policy.description,
            )
            query = self._paginator.update_query(query, **kwargs)

            policies = []
            for policy in query.all():
                if policy.acl_templates == [None]:
                    acl_templates = []
                else:
                    acl_templates = policy.acl_templates

                body = {
                    'uuid': policy.uuid,
                    'name': policy.name,
                    'description': policy.description,
                    'acl_templates': acl_templates,
                }
                policies.append(body)

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
                    raise DuplicatePolicyException(name)
                raise

            self._dissociate_all_acl_templates(s, policy_uuid)
            self._associate_acl_templates(s, policy_uuid, acl_templates)

    def _associate_acl_templates(self, session, policy_uuid, acl_templates):
        ids = self._create_or_find_acl_templates(session, acl_templates)
        template_policies = [ACLTemplatePolicy(policy_uuid=policy_uuid, template_id=id_) for id_ in ids]
        session.add_all(template_policies)

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
        s.query(ACLTemplatePolicy).filter(filter_).delete()

    def _insert_acl_template(self, s, template):
        tpl = ACLTemplate(template=template)
        s.add(tpl)
        s.commit()
        return tpl.id_

    def _policy_exists(self, s, policy_uuid):
        policy_count = s.query(Policy).filter(Policy.uuid == policy_uuid).count()
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
        token.acls = [ACL(token_uuid=token.uuid, value=acl) for acl in body.get('acls') or []]
        with self.new_session() as s:
            s.add(token)
            s.commit()
            return token.uuid

    def get(self, token_uuid):
        with self.new_session() as s:
            token = s.query(TokenModel).get(token_uuid)
            if token:
                return {
                    'uuid': token.uuid,
                    'auth_id': token.auth_id,
                    'xivo_user_uuid': token.user_uuid,
                    'xivo_uuid': token.xivo_uuid,
                    'issued_t': token.issued_t,
                    'expire_t': token.expire_t,
                    'acls': [acl.value for acl in token.acls],
                }

            raise UnknownTokenException()

    def delete(self, token_uuid):
        filter_ = TokenModel.uuid == token_uuid

        with self.new_session() as s:
            s.query(TokenModel).filter(filter_).delete()

    def delete_expired_tokens(self):
        filter_ = TokenModel.expire_t < time.time()

        with self.new_session() as s:
            s.query(TokenModel).filter(filter_).delete()


class _UserCRUD(_CRUD):

    constraint_to_column_map = dict(
        auth_user_username_key='username',
        auth_email_address_key='email_address',
    )

    def __init__(self, *args, **kwargs):
        super(_UserCRUD, self).__init__(*args, **kwargs)
        column_map = dict(
            username=User.username,
        )
        self._paginator = QueryPaginator(column_map)

    def _new_search_filter(self, search=None, **ignored):
        if not search:
            return text('true')

        return or_(
            User.uuid.ilike(search),
            User.username.ilike(search),
            Email.address.ilike(search),
        )

    def _new_strict_filter(self, uuid=None, username=None, email_address=None, **ignored):
        filter_ = text('true')
        if uuid:
            filter_ = and_(filter_, User.uuid == uuid)
        if username:
            filter_ = and_(filter_, User.username == username)
        if email_address:
            filter_ = and_(filter_, Email.address == email_address)
        return filter_

    def count(self, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = self._new_strict_filter(**kwargs)
            search_filter = self._new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        with self.new_session() as s:
            return s.query(User).join(
                Email, Email.user_uuid == User.uuid
            ).filter(filter_).count()

    def create(self, username, email_address, hash_, salt):
        with self.new_session() as s:
            try:
                email = Email(
                    address=email_address,
                )
                s.add(email)
                s.flush()
                user = User(
                    username=username,
                    password_hash=hash_,
                    password_salt=salt,
                    main_email_uuid=email.uuid,
                )
                s.add(user)
                s.flush()
                email.user_uuid = user.uuid
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    column = self.constraint_to_column_map.get(e.orig.diag.constraint_name)
                    value = locals().get(column)
                    if column:
                        raise ConflictException('users', column, value)
                raise
            return user.uuid

    def delete(self, user_uuid):
        with self.new_session() as s:
            nb_deleted = s.query(User).filter(User.uuid == user_uuid).delete()

        if not nb_deleted:
            raise UnknownUserException(user_uuid)

    def list_(self, **kwargs):
        users = dict()

        search_filter = self._new_search_filter(**kwargs)
        strict_filter = self._new_strict_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        with self.new_session() as s:
            query = s.query(
                User.uuid,
                User.username,
                User.main_email_uuid,
                Email.uuid,
                Email.address,
                Email.confirmed,
            ).join(Email, Email.user_uuid == User.uuid).filter(filter_)
            query = self._paginator.update_query(query, **kwargs)
            rows = query.all()

            for user_uuid, username, main_email_uuid, email_uuid, address, confirmed in rows:
                if user_uuid not in users:
                    users[user_uuid] = dict(
                        username=username,
                        uuid=user_uuid,
                        email_addresses=[],
                    )

                email = dict(
                    address=address,
                    main=main_email_uuid == email_uuid,
                    confirmed=confirmed,
                )
                users[user_uuid]['email_addresses'].append(email)

        return users.values()


class QueryPaginator(object):

    _valid_directions = ['asc', 'desc']

    def __init__(self, column_map):
        self._column_map = column_map

    def update_query(self, query, limit, offset, order, direction, **ignored):
        order_field = self._column_map.get(order)
        if not order_field:
            raise InvalidSortColumnException(order)

        if direction not in self._valid_directions:
            raise InvalidSortDirectionException(direction)

        offset = self._check_valid_limit_or_offset(offset, 0, InvalidOffsetException)
        limit = self._check_valid_limit_or_offset(limit, None, InvalidLimitException)
        order_clause = order_field.asc() if direction == 'asc' else order_field.desc()

        return query.order_by(order_clause).limit(limit).offset(offset)

    def _check_valid_limit_or_offset(self, value, default, exception):
        if value is True or value is False:
            raise exception(value)

        if value is None:
            return default

        try:
            value = int(value)
        except ValueError:
            raise exception(value)

        if value < 0:
            raise exception(value)

        return value
