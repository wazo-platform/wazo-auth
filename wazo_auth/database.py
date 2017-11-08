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
from collections import OrderedDict
from contextlib import contextmanager
from sqlalchemy import and_, create_engine, exc, func, or_, text
from sqlalchemy.orm import sessionmaker, scoped_session
from .models import (
    ACL,
    ACLTemplate,
    ACLTemplatePolicy,
    Email,
    Policy,
    Tenant,
    TenantUser,
    Token as TokenModel,
    User,
    UserEmail,
    UserPolicy,
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
    UnknownTenantException,
    UnknownTenantUserException,
    UnknownTokenException,
    UnknownUserException,
    UnknownUserPolicyException,
    UnknownUsernameException,
)

logger = logging.getLogger(__name__)


class SearchFilter(object):

    def __init__(self, *columns):
        self._columns = columns

    def new_filter(self, search=None, **ignored):
        if search is None:
            return text('true')

        if not search:
            pattern = '%'
        else:
            words = [w for w in search.split(' ') if w]
            pattern = '%{}%'.format('%'.join(words))

        return or_(column.ilike(pattern) for column in self._columns)


class Storage(object):

    def __init__(self, policy_crud, token_crud, user_crud, tenant_crud):
        self._policy_crud = policy_crud
        self._token_crud = token_crud
        self._user_crud = user_crud
        self._tenant_crud = tenant_crud

    def add_policy_acl_template(self, policy_uuid, acl_template):
        self._policy_crud.associate_policy_template(policy_uuid, acl_template)

    def count_policies(self, search):
        return self._policy_crud.count(search)

    def delete_policy_acl_template(self, policy_uuid, acl_template):
        self._policy_crud.dissociate_policy_template(policy_uuid, acl_template)

    def get_policy(self, policy_uuid):
        if self._is_uuid(policy_uuid):
            for policy in self._policy_crud.get(uuid=policy_uuid):
                return policy
        raise UnknownPolicyException()

    def get_policy_by_name(self, policy_name):
        for policy in self._policy_crud.get(search=policy_name):
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

    def list_policies(self, **kwargs):
        return self._policy_crud.get(**kwargs)

    def update_policy(self, policy_uuid, name, description, acl_templates):
        self._policy_crud.update(policy_uuid, name, description, acl_templates)

    def tenant_add_user(self, tenant_uuid, user_uuid):
        self._tenant_crud.add_user(tenant_uuid, user_uuid)

    def tenant_count(self, **kwargs):
        return self._tenant_crud.count(**kwargs)

    def tenant_count_users(self, tenant_uuid, **kwargs):
        return self._tenant_crud.count_users(tenant_uuid, **kwargs)

    def tenant_create(self, name):
        tenant_uuid = self._tenant_crud.create(name)
        return dict(
            uuid=tenant_uuid,
            name=name,
        )

    def tenant_delete(self, tenant_uuid):
        return self._tenant_crud.delete(tenant_uuid)

    def tenant_list(self, **kwargs):
        return self._tenant_crud.list_(**kwargs)

    def tenant_remove_user(self, tenant_uuid, user_uuid):
        self._tenant_crud.remove_user(tenant_uuid, user_uuid)

    def user_add_policy(self, user_uuid, policy_uuid):
        self._user_crud.add_policy(user_uuid, policy_uuid)

    def user_remove_policy(self, user_uuid, policy_uuid):
        self._user_crud.remove_policy(user_uuid, policy_uuid)

    def user_count(self, **kwargs):
        return self._user_crud.count(**kwargs)

    def user_count_policies(self, user_uuid, **kwargs):
        return self._user_crud.count_policies(user_uuid, **kwargs)

    def user_list_policies(self, user_uuid, **kwargs):
        return self._policy_crud.get(user_uuid=user_uuid, **kwargs)

    def user_delete(self, user_uuid):
        self._user_crud.delete(user_uuid)

    def user_create(self, username, email_address, hash_, salt):
        user_uuid = self._user_crud.create(username, email_address, hash_, salt)
        email = dict(
            address=email_address,
            confirmed=False,
            main=True,
        )
        return dict(
            uuid=user_uuid,
            username=username,
            emails=[email],
        )

    def user_get_credentials(self, username):
        return self._user_crud.get_credentials(username)

    def user_list(self, **kwargs):
        return self._user_crud.list_(**kwargs)

    def remove_token(self, token_id):
        self._token_crud.delete(token_id)

    def remove_expired_tokens(self):
        self._token_crud.delete_expired_tokens()

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
        tenant_crud = _TenantCRUD(config['db_uri'])
        return cls(policy_crud, token_crud, user_crud, tenant_crud)


class _CRUD(object):

    _UNIQUE_CONSTRAINT_CODE = '23505'
    _FKEY_CONSTRAINT_CODE = '23503'

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
        except Exception:
            session.rollback()
            raise
        finally:
            self._Session.remove()


class _PolicyCRUD(_CRUD):

    search_filter = SearchFilter(Policy.name, Policy.description)

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

    def count(self, search_pattern):
        filter_ = self._new_search_filter(search=search_pattern)
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

    def get(self, **kwargs):
        strict_filter = self._new_strict_filter(**kwargs)
        search_filter = self._new_search_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)
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
            ).outerjoin(
                UserPolicy,
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

    @classmethod
    def _new_search_filter(cls, **kwargs):
        return cls.search_filter.new_filter(**kwargs)

    @staticmethod
    def _new_strict_filter(uuid=None, name=None, user_uuid=None, **ignored):
        filter_ = text('true')
        if uuid:
            filter_ = and_(filter_, Policy.uuid == uuid)
        if name:
            filter_ = and_(filter_, Policy.name == name)
        if user_uuid:
            filter_ = and_(filter_, UserPolicy.user_uuid == user_uuid)
        return filter_


class _TenantCRUD(_CRUD):

    constraint_to_column_map = dict(
        auth_tenant_name_key='name',
    )
    search_filter = SearchFilter(Tenant.name)

    def __init__(self, *args, **kwargs):
        super(_TenantCRUD, self).__init__(*args, **kwargs)
        column_map = dict(
            name=Tenant.name,
        )
        self._paginator = QueryPaginator(column_map)

    def add_user(self, tenant_uuid, user_uuid):
        tenant_user = TenantUser(tenant_uuid=tenant_uuid, user_uuid=user_uuid)
        with self.new_session() as s:
            s.add(tenant_user)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    # This association already exists.
                    s.rollback()
                    return
                if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                    constraint = e.orig.diag.constraint_name
                    if constraint == 'auth_tenant_user_tenant_uuid_fkey':
                        raise UnknownTenantException(tenant_uuid)
                    elif constraint == 'auth_tenant_user_user_uuid_fkey':
                        raise UnknownUserException(user_uuid)
                raise

    def count(self, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = self._new_strict_filter(**kwargs)
            search_filter = self._new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        with self.new_session() as s:
            return s.query(Tenant).filter(filter_).count()

    def count_users(self, tenant_uuid, **kwargs):
        logger.debug('filtering %s', kwargs)
        filtered = kwargs.get('filtered')
        if filtered is not False:
            logger.debug('filtering')
            strict_filter = _UserCRUD._new_strict_filter(**kwargs)
            search_filter = _UserCRUD._new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, TenantUser.tenant_uuid == tenant_uuid)
        logger.debug(filter_)

        with self.new_session() as s:
            return s.query(
                TenantUser
            ).join(
                User
            ).join(
                UserEmail
            ).join(
                Email
            ).filter(filter_).count()

    def create(self, name):
        tenant = Tenant(name=name)
        with self.new_session() as s:
            s.add(tenant)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    column = self.constraint_to_column_map.get(e.orig.diag.constraint_name)
                    value = locals().get(column)
                    if column:
                        raise ConflictException('tenants', column, value)
                raise
            return tenant.uuid

    def delete(self, uuid):
        with self.new_session() as s:
            nb_deleted = s.query(Tenant).filter(Tenant.uuid == uuid).delete()

        if not nb_deleted:
            raise UnknownTenantException(uuid)

    def list_(self, **kwargs):
        search_filter = self._new_search_filter(**kwargs)
        strict_filter = self._new_strict_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        with self.new_session() as s:
            query = s.query(
                Tenant.uuid,
                Tenant.name,
            ).filter(filter_)
            query = self._paginator.update_query(query, **kwargs)

            return [{'uuid': uuid, 'name': name} for uuid, name in query.all()]

    @classmethod
    def _new_search_filter(cls, **kwargs):
        return cls.search_filter.new_filter(**kwargs)

    def remove_user(self, tenant_uuid, user_uuid):
        filter_ = and_(TenantUser.user_uuid == user_uuid, TenantUser.tenant_uuid == tenant_uuid)
        with self.new_session() as s:
            nb_deleted = s.query(TenantUser).filter(filter_).delete()

        if not nb_deleted:
            raise UnknownTenantUserException(tenant_uuid, user_uuid)

    @staticmethod
    def _new_strict_filter(uuid=None, name=None, **ignored):
        filter_ = text('true')
        if uuid:
            filter_ = and_(filter_, Tenant.uuid == uuid)
        if name:
            filter_ = and_(filter_, Tenant.name == name)
        return filter_


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
    search_filter = SearchFilter(User.username, Email.address)

    def __init__(self, *args, **kwargs):
        super(_UserCRUD, self).__init__(*args, **kwargs)
        column_map = dict(
            username=User.username,
        )
        self._paginator = QueryPaginator(column_map)

    @classmethod
    def _new_search_filter(cls, **kwargs):
        return cls.search_filter.new_filter(**kwargs)

    @staticmethod
    def _new_strict_filter(uuid=None, username=None, email_address=None, tenant_uuid=None, **ignored):
        filter_ = text('true')
        if uuid:
            filter_ = and_(filter_, User.uuid == uuid)
        if username:
            filter_ = and_(filter_, User.username == username)
        if email_address:
            filter_ = and_(filter_, Email.address == email_address)
        if tenant_uuid:
            filter_ = and_(filter_, TenantUser.tenant_uuid == tenant_uuid)
        return filter_

    def add_policy(self, user_uuid, policy_uuid):
        user_policy = UserPolicy(user_uuid=user_uuid, policy_uuid=policy_uuid)
        with self.new_session() as s:
            s.add(user_policy)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    # This association already exists.
                    s.rollback()
                    return
                if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                    constraint = e.orig.diag.constraint_name
                    if constraint == 'auth_user_policy_user_uuid_fkey':
                        raise UnknownUserException(user_uuid)
                    elif constraint == 'auth_user_policy_policy_uuid_fkey':
                        raise UnknownPolicyException(policy_uuid)
                raise

    def remove_policy(self, user_uuid, policy_uuid):
        with self.new_session() as s:
            nb_deleted = s.query(UserPolicy).filter(
                and_(
                    UserPolicy.user_uuid == user_uuid,
                    UserPolicy.policy_uuid == policy_uuid,
                )
            ).delete()

        if nb_deleted == 0:
            raise UnknownUserPolicyException(user_uuid, policy_uuid)

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
                UserEmail, UserEmail.user_uuid == User.uuid,
            ).join(
                Email, Email.uuid == UserEmail.email_uuid
            ).filter(filter_).count()

    def count_policies(self, user_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = _PolicyCRUD._new_strict_filter(**kwargs)
            search_filter = _PolicyCRUD._new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, UserPolicy.user_uuid == user_uuid)

        with self.new_session() as s:
            return s.query(Policy).join(
                UserPolicy, UserPolicy.policy_uuid == Policy.uuid,
            ).filter(filter_).count()

    def create(self, username, email_address, hash_, salt):
        with self.new_session() as s:
            try:
                email = Email(
                    address=email_address,
                )
                s.add(email)
                user = User(
                    username=username,
                    password_hash=hash_,
                    password_salt=salt,
                )
                s.add(user)
                s.flush()
                user_email = UserEmail(
                    user_uuid=user.uuid,
                    email_uuid=email.uuid,
                    main=True,
                )
                s.add(user_email)
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
            rows = s.query(UserEmail.email_uuid).filter(UserEmail.user_uuid == user_uuid).all()
            email_ids = [row.email_uuid for row in rows]
            if email_ids:
                s.query(Email).filter(Email.uuid.in_(email_ids)).delete(synchronize_session=False)
            nb_deleted = s.query(User).filter(User.uuid == user_uuid).delete()

        if not nb_deleted:
            raise UnknownUserException(user_uuid)

    def get_credentials(self, username):
        filter_ = self._new_strict_filter(username=username)
        with self.new_session() as s:
            query = s.query(
                User.password_salt,
                User.password_hash,
            ).filter(filter_)

            for row in query.all():
                return row.password_hash, row.password_salt

            raise UnknownUsernameException(username)

    def list_(self, **kwargs):
        users = OrderedDict()

        search_filter = self._new_search_filter(**kwargs)
        strict_filter = self._new_strict_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        with self.new_session() as s:
            query = s.query(
                User.uuid,
                User.username,
                UserEmail.main,
                Email.uuid,
                Email.address,
                Email.confirmed,
            ).join(
                UserEmail, User.uuid == UserEmail.user_uuid,
            ).join(
                Email, Email.uuid == UserEmail.email_uuid,
            ).outerjoin(
                TenantUser,
            ).filter(filter_)
            query = self._paginator.update_query(query, **kwargs)
            rows = query.all()

            for user_uuid, username, main_email, email_uuid, address, confirmed in rows:
                if user_uuid not in users:
                    users[user_uuid] = dict(
                        username=username,
                        uuid=user_uuid,
                        emails=[],
                    )

                email = dict(
                    address=address,
                    main=main_email,
                    confirmed=confirmed,
                )
                users[user_uuid]['emails'].append(email)

        return users.values()

    def list_policies(self, user_uuid, **kwargs):
        strict_filter = _PolicyCRUD._new_strict_filter(**kwargs)
        search_filter = _PolicyCRUD._new_search_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        filter_ = and_(filter_, UserPolicy.user_uuid == user_uuid)

        with self.new_session() as s:
            return s.query(Policy).join(
                UserPolicy, UserPolicy.policy_uuid == Policy.uuid,
            ).filter(filter_).count()


class QueryPaginator(object):

    _valid_directions = ['asc', 'desc']

    def __init__(self, column_map):
        self._column_map = column_map

    def update_query(self, query, limit=None, offset=None, order=None, direction=None, **ignored):
        if order and direction:
            order_field = self._column_map.get(order)
            if not order_field:
                raise InvalidSortColumnException(order)

            if direction not in self._valid_directions:
                raise InvalidSortDirectionException(direction)

            order_clause = order_field.asc() if direction == 'asc' else order_field.desc()
            query = query.order_by(order_clause)

        if limit is not None:
            limit = self._check_valid_limit_or_offset(limit, None, InvalidLimitException)
            query = query.limit(limit)

        if offset is not None:
            offset = self._check_valid_limit_or_offset(offset, 0, InvalidOffsetException)
            query = query.offset(offset)

        return query

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
