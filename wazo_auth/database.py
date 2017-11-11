# -*- coding: utf-8 -*-
#
# Copyright 2016-2017 The Wazo Authors  (see the AUTHORS file)
#
# SPDX-License-Identifier: GPL-3.0+

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
    Group,
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
    DuplicateGroupException,
    DuplicatePolicyException,
    DuplicateTemplateException,
    InvalidLimitException,
    InvalidOffsetException,
    InvalidSortColumnException,
    InvalidSortDirectionException,
    UnknownGroupException,
    UnknownPolicyException,
    UnknownTenantException,
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


class DAO(object):

    def __init__(self, policy_crud, token_crud, user_crud, tenant_crud, group_crud):
        self.policy = policy_crud
        self.token = token_crud
        self.user = user_crud
        self.tenant = tenant_crud
        self.group = group_crud

    def add_policy_acl_template(self, policy_uuid, acl_template):
        self.policy.associate_policy_template(policy_uuid, acl_template)

    def count_policies(self, search):
        return self.policy.count(search)

    def delete_policy_acl_template(self, policy_uuid, acl_template):
        self.policy.dissociate_policy_template(policy_uuid, acl_template)

    def get_policy(self, policy_uuid):
        if self._is_uuid(policy_uuid):
            for policy in self.policy.get(uuid=policy_uuid):
                return policy
        raise UnknownPolicyException()

    def get_policy_by_name(self, policy_name):
        for policy in self.policy.get(search=policy_name):
            if policy['name'] == policy_name:
                return policy
        raise UnknownPolicyException()

    def get_token(self, token_id):
        token_data = self.token.get(token_id)
        if not token_data:
            raise UnknownTokenException()

        id_ = token_data.pop('uuid')
        return Token(id_, **token_data)

    def create_policy(self, name, description, acl_templates):
        return self.policy.create(name, description, acl_templates)

    def create_token(self, token_payload):
        token_data = token_payload.__dict__
        token_uuid = self.token.create(token_data)
        return Token(token_uuid, **token_data)

    def delete_policy(self, policy_uuid):
        self.policy.delete(policy_uuid)

    def group_count(self, **kwargs):
        return self.group.count(**kwargs)

    def group_create(self, **kwargs):
        group_uuid = self.group.create(**kwargs)
        return dict(uuid=group_uuid, **kwargs)

    def group_delete(self, group_uuid):
        return self.group.delete(group_uuid)

    def group_get(self, group_uuid):
        groups = self.group.list_(uuid=group_uuid, limit=1)
        for group in groups:
            return group
        raise UnknownGroupException(group_uuid)

    def group_list(self, **kwargs):
        return self.group.list_(**kwargs)

    def group_update(self, group_uuid, **kwargs):
        return self.group.update(group_uuid, **kwargs)

    def list_policies(self, **kwargs):
        return self.policy.get(**kwargs)

    def update_policy(self, policy_uuid, name, description, acl_templates):
        self.policy.update(policy_uuid, name, description, acl_templates)

    def tenant_add_user(self, tenant_uuid, user_uuid):
        self.tenant.add_user(tenant_uuid, user_uuid)

    def tenant_count(self, **kwargs):
        return self.tenant.count(**kwargs)

    def tenant_count_users(self, tenant_uuid, **kwargs):
        return self.tenant.count_users(tenant_uuid, **kwargs)

    def tenant_create(self, name):
        tenant_uuid = self.tenant.create(name)
        return dict(
            uuid=tenant_uuid,
            name=name,
        )

    def tenant_delete(self, tenant_uuid):
        return self.tenant.delete(tenant_uuid)

    def tenant_list(self, **kwargs):
        return self.tenant.list_(**kwargs)

    def tenant_remove_user(self, tenant_uuid, user_uuid):
        self.tenant.remove_user(tenant_uuid, user_uuid)

    def user_add_policy(self, user_uuid, policy_uuid):
        self.user.add_policy(user_uuid, policy_uuid)

    def user_remove_policy(self, user_uuid, policy_uuid):
        self.user.remove_policy(user_uuid, policy_uuid)

    def user_count(self, **kwargs):
        return self.user.count(**kwargs)

    def user_count_policies(self, user_uuid, **kwargs):
        return self.user.count_policies(user_uuid, **kwargs)

    def user_count_tenants(self, user_uuid, **kwargs):
        return self.user.count_tenants(user_uuid, **kwargs)

    def user_list_policies(self, user_uuid, **kwargs):
        return self.policy.get(user_uuid=user_uuid, **kwargs)

    def user_list_tenants(self, user_uuid, **kwargs):
        return self.tenant.list_(user_uuid=user_uuid, **kwargs)

    def user_delete(self, user_uuid):
        self.user.delete(user_uuid)

    def user_create(self, username, email_address, hash_, salt):
        user_uuid = self.user.create(username, email_address, hash_, salt)
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
        return self.user.get_credentials(username)

    def user_list(self, **kwargs):
        return self.user.list_(**kwargs)

    def remove_token(self, token_id):
        self.token.delete(token_id)

    def remove_expired_tokens(self):
        self.token.delete_expired_tokens()

    @staticmethod
    def _is_uuid(value):
        try:
            uuid.UUID(value)
            return True
        except (ValueError, TypeError):
            return False

    @classmethod
    def from_config(cls, config):
        group = _GroupCRUD(config['db_uri'])
        policy = _PolicyCRUD(config['db_uri'])
        token = _TokenCRUD(config['db_uri'])
        user = _UserCRUD(config['db_uri'])
        tenant = _TenantCRUD(config['db_uri'])
        return cls(policy, token, user, tenant, group)


class _CRUD(object):

    _UNIQUE_CONSTRAINT_CODE = '23505'
    _FKEY_CONSTRAINT_CODE = '23503'
    search_filter = SearchFilter()

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

    @classmethod
    def new_search_filter(cls, **kwargs):
        return cls.search_filter.new_filter(**kwargs)


class _PaginatorMixin(object):

    column_map = dict()

    def __init__(self, *args, **kwargs):
        super(_PaginatorMixin, self).__init__(*args, **kwargs)
        self._paginator = QueryPaginator(self.column_map)


class _GroupCRUD(_PaginatorMixin, _CRUD):

    constraint_to_column_map = dict(
        auth_group_name_key='name',
    )
    search_filter = SearchFilter(Group.name)
    column_map = dict(
        name=Group.name,
        uuid=Group.uuid,
    )

    def count(self, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = self._new_strict_filter(**kwargs)
            search_filter = self.new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        with self.new_session() as s:
            return s.query(Group).filter(filter_).count()

    def create(self, name, **ignored):
        group = Group(name=name)
        with self.new_session() as s:
            s.add(group)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    column = self.constraint_to_column_map.get(e.orig.diag.constraint_name)
                    value = locals().get(column)
                    if column:
                        raise ConflictException('groups', column, value)
                raise
            return group.uuid

    def delete(self, uuid):
        with self.new_session() as s:
            nb_deleted = s.query(Group).filter(Group.uuid == str(uuid)).delete()

        if not nb_deleted:
            raise UnknownGroupException(uuid)

    def list_(self, **kwargs):
        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self._new_strict_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        with self.new_session() as s:
            query = s.query(
                Group.uuid,
                Group.name,
            ).filter(filter_)
            query = self._paginator.update_query(query, **kwargs)

            return [{'uuid': uuid, 'name': name} for uuid, name in query.all()]

    def update(self, group_uuid, **body):
        with self.new_session() as s:
            filter_ = Group.uuid == str(group_uuid)
            try:
                affected_rows = s.query(Group).filter(filter_).update(body)
                if not affected_rows:
                    raise UnknownGroupException(group_uuid)

                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    column = self.constraint_to_column_map.get(e.orig.diag.constraint_name)
                    value = body.get(column)
                    if column:
                        raise ConflictException('groups', column, value)
                raise

        return dict(uuid=str(group_uuid), **body)

    @staticmethod
    def _new_strict_filter(uuid=None, name=None, **ignored):
        filter_ = text('true')
        if uuid:
            filter_ = and_(filter_, Group.uuid == str(uuid))
        if name:
            filter_ = and_(filter_, Group.name == name)
        return filter_


class _PolicyCRUD(_PaginatorMixin, _CRUD):

    search_filter = SearchFilter(Policy.name, Policy.description)
    column_map = dict(
        name=Policy.name,
        description=Policy.description,
        uuid=Policy.uuid,
    )

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
        filter_ = self.new_search_filter(search=search_pattern)
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
        search_filter = self.new_search_filter(**kwargs)
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


class _TenantCRUD(_PaginatorMixin, _CRUD):

    constraint_to_column_map = dict(
        auth_tenant_name_key='name',
    )
    search_filter = SearchFilter(Tenant.name)
    column_map = dict(
        name=Tenant.name,
    )

    def add_user(self, tenant_uuid, user_uuid):
        tenant_user = TenantUser(tenant_uuid=str(tenant_uuid), user_uuid=str(user_uuid))
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
            search_filter = self.new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        with self.new_session() as s:
            return s.query(Tenant).filter(filter_).count()

    def count_users(self, tenant_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = _UserCRUD._new_strict_filter(**kwargs)
            search_filter = _UserCRUD.new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, TenantUser.tenant_uuid == str(tenant_uuid))

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
            nb_deleted = s.query(Tenant).filter(Tenant.uuid == str(uuid)).delete()

        if not nb_deleted:
            if not self.list_(uuid=uuid):
                raise UnknownTenantException(uuid)
            else:
                raise UnknownUserException(uuid)

    def list_(self, **kwargs):
        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self._new_strict_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        with self.new_session() as s:
            query = s.query(
                Tenant.uuid,
                Tenant.name,
            ).outerjoin(TenantUser).filter(filter_)
            query = self._paginator.update_query(query, **kwargs)

            return [{'uuid': uuid, 'name': name} for uuid, name in query.all()]

    def remove_user(self, tenant_uuid, user_uuid):
        filter_ = and_(
            TenantUser.user_uuid == str(user_uuid),
            TenantUser.tenant_uuid == str(tenant_uuid),
        )
        with self.new_session() as s:
            nb_deleted = s.query(TenantUser).filter(filter_).delete()

        if not nb_deleted:
            if not self.list_(uuid=tenant_uuid):
                raise UnknownTenantException(tenant_uuid)
            else:
                raise UnknownUserException(user_uuid)

    @staticmethod
    def _new_strict_filter(uuid=None, name=None, user_uuid=None, **ignored):
        filter_ = text('true')
        if uuid:
            filter_ = and_(filter_, Tenant.uuid == str(uuid))
        if name:
            filter_ = and_(filter_, Tenant.name == name)
        if user_uuid:
            filter_ = and_(filter_, TenantUser.user_uuid == str(user_uuid))
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


class _UserCRUD(_PaginatorMixin, _CRUD):

    constraint_to_column_map = dict(
        auth_user_username_key='username',
        auth_email_address_key='email_address',
    )
    search_filter = SearchFilter(User.username, Email.address)
    column_map = dict(
        username=User.username,
    )

    @staticmethod
    def _new_strict_filter(uuid=None, username=None, email_address=None, tenant_uuid=None, **ignored):
        filter_ = text('true')
        if uuid:
            filter_ = and_(filter_, User.uuid == str(uuid))
        if username:
            filter_ = and_(filter_, User.username == username)
        if email_address:
            filter_ = and_(filter_, Email.address == email_address)
        if tenant_uuid:
            filter_ = and_(filter_, TenantUser.tenant_uuid == str(tenant_uuid))
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
            search_filter = self.new_search_filter(**kwargs)
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
            search_filter = _PolicyCRUD.new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, UserPolicy.user_uuid == user_uuid)

        with self.new_session() as s:
            return s.query(Policy).join(
                UserPolicy, UserPolicy.policy_uuid == Policy.uuid,
            ).filter(filter_).count()

    def count_tenants(self, user_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = _TenantCRUD._new_strict_filter(**kwargs)
            search_filter = _TenantCRUD.new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, TenantUser.user_uuid == str(user_uuid))

        with self.new_session() as s:
            return s.query(Tenant).join(TenantUser).filter(filter_).count()

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

        search_filter = self.new_search_filter(**kwargs)
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
