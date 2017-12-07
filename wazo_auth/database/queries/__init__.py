# -*- coding: utf-8 -*-
# Copyright 2016-2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging
import time
from collections import OrderedDict
from sqlalchemy import and_, exc, func, text
from .base import BaseDAO, SearchFilter
from .external_auth import ExternalAuthDAO
from ..models import (
    ACL,
    ACLTemplate,
    ACLTemplatePolicy,
    Email,
    Group,
    GroupPolicy,
    Policy,
    Tenant,
    TenantUser,
    Token as TokenModel,
    User,
    UserEmail,
    UserGroup,
    UserPolicy,
)
from ...exceptions import (
    ConflictException,
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
    UnknownUsernameException,
)

logger = logging.getLogger(__name__)


class DAO(object):

    def __init__(self, policy_dao, token_dao, user_dao, tenant_dao, group_dao, external_auth_dao):
        self.external_auth = external_auth_dao
        self.policy = policy_dao
        self.token = token_dao
        self.user = user_dao
        self.tenant = tenant_dao
        self.group = group_dao

    @classmethod
    def from_config(cls, config):
        external_auth = ExternalAuthDAO(config['db_uri'])
        group = _GroupDAO(config['db_uri'])
        policy = _PolicyDAO(config['db_uri'])
        token = _TokenDAO(config['db_uri'])
        user = _UserDAO(config['db_uri'])
        tenant = _TenantDAO(config['db_uri'])
        return cls(policy, token, user, tenant, group, external_auth)


class _PaginatorMixin(object):

    column_map = dict()

    def __init__(self, *args, **kwargs):
        super(_PaginatorMixin, self).__init__(*args, **kwargs)
        self._paginator = QueryPaginator(self.column_map)


class _GroupDAO(_PaginatorMixin, BaseDAO):

    constraint_to_column_map = dict(
        auth_group_name_key='name',
    )
    search_filter = SearchFilter(Group.name)
    column_map = dict(
        name=Group.name,
        uuid=Group.uuid,
    )

    def add_policy(self, group_uuid, policy_uuid):
        group_policy = GroupPolicy(policy_uuid=str(policy_uuid), group_uuid=str(group_uuid))
        with self.new_session() as s:
            s.add(group_policy)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    # This association already exists.
                    s.rollback()
                    return
                if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                    constraint = e.orig.diag.constraint_name
                    if constraint == 'auth_group_policy_group_uuid_fkey':
                        raise UnknownGroupException(group_uuid)
                    elif constraint == 'auth_group_policy_policy_uuid_fkey':
                        raise UnknownPolicyException(policy_uuid)
                raise

    def add_user(self, group_uuid, user_uuid):
        user_group = UserGroup(user_uuid=str(user_uuid), group_uuid=str(group_uuid))
        with self.new_session() as s:
            s.add(user_group)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    # This association already exists.
                    s.rollback()
                    return
                if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                    constraint = e.orig.diag.constraint_name
                    if constraint == 'auth_user_group_group_uuid_fkey':
                        raise UnknownGroupException(group_uuid)
                    elif constraint == 'auth_user_group_user_uuid_fkey':
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
            return s.query(Group).filter(filter_).count()

    def count_policies(self, group_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = _PolicyDAO._new_strict_filter(**kwargs)
            search_filter = _PolicyDAO.new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, GroupPolicy.group_uuid == str(group_uuid))

        with self.new_session() as s:
            return s.query(GroupPolicy).join(Policy).filter(filter_).count()

    def count_users(self, group_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = _UserDAO._new_strict_filter(**kwargs)
            search_filter = _UserDAO.new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, UserGroup.group_uuid == str(group_uuid))

        with self.new_session() as s:
            return s.query(UserGroup).join(User).join(UserEmail).join(Email).filter(filter_).count()

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

    def exists(self, uuid):
        return self.count(uuid=uuid) > 0

    def list_(self, **kwargs):
        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self._new_strict_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        with self.new_session() as s:
            query = s.query(
                Group.uuid,
                Group.name,
            ).outerjoin(UserGroup).filter(filter_)
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

    def remove_policy(self, group_uuid, policy_uuid):
        filter_ = and_(
            GroupPolicy.policy_uuid == str(policy_uuid),
            GroupPolicy.group_uuid == str(group_uuid),
        )

        with self.new_session() as s:
            return s.query(GroupPolicy).filter(filter_).delete()

    def remove_user(self, group_uuid, user_uuid):
        filter_ = and_(
            UserGroup.user_uuid == str(user_uuid),
            UserGroup.group_uuid == str(group_uuid),
        )

        with self.new_session() as s:
            return s.query(UserGroup).filter(filter_).delete()

    @staticmethod
    def _new_strict_filter(uuid=None, name=None, user_uuid=None, **ignored):
        filter_ = text('true')
        if uuid:
            filter_ = and_(filter_, Group.uuid == str(uuid))
        if name:
            filter_ = and_(filter_, Group.name == name)
        if user_uuid:
            filter_ = and_(filter_, UserGroup.user_uuid == str(user_uuid))
        return filter_


class _PolicyDAO(_PaginatorMixin, BaseDAO):

    search_filter = SearchFilter(Policy.name, Policy.description)
    column_map = dict(
        name=Policy.name,
        description=Policy.description,
        uuid=Policy.uuid,
    )

    def associate_policy_template(self, policy_uuid, acl_template):
        with self.new_session() as s:
            self._associate_acl_templates(s, policy_uuid, [acl_template])
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    raise DuplicateTemplateException(acl_template)
                if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                    constraint = e.orig.diag.constraint_name
                    if constraint == 'auth_policy_template_policy_uuid_fkey':
                        raise UnknownPolicyException(policy_uuid)
                raise

    def dissociate_policy_template(self, policy_uuid, acl_template):
        with self.new_session() as s:
            filter_ = and_(
                ACLTemplate.template == acl_template,
                ACLTemplatePolicy.policy_uuid == policy_uuid,
            )

            template_id = s.query(ACLTemplate.id_).join(ACLTemplatePolicy).filter(filter_).first()
            if not template_id:
                return 0

            filter_ = and_(
                ACLTemplatePolicy.policy_uuid == policy_uuid,
                ACLTemplatePolicy.template_id == template_id,
            )
            return s.query(ACLTemplatePolicy).filter(filter_).delete()

    def count(self, search, **ignored):
        filter_ = self.new_search_filter(search=search)
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
            raise UnknownPolicyException(policy_uuid)

    def exists(self, uuid):
        with self.new_session() as s:
            return self._policy_exists(s, uuid)

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
            ).outerjoin(
                GroupPolicy,
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
                raise UnknownPolicyException(policy_uuid)

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
        policy_count = s.query(Policy).filter(Policy.uuid == str(policy_uuid)).count()
        return policy_count > 0

    @staticmethod
    def _new_strict_filter(uuid=None, name=None, user_uuid=None, group_uuid=None, **ignored):
        filter_ = text('true')
        if uuid:
            filter_ = and_(filter_, Policy.uuid == str(uuid))
        if name:
            filter_ = and_(filter_, Policy.name == name)
        if user_uuid:
            filter_ = and_(filter_, UserPolicy.user_uuid == user_uuid)
        if group_uuid:
            filter_ = and_(filter_, GroupPolicy.group_uuid == str(group_uuid))
        return filter_


class _TenantDAO(_PaginatorMixin, BaseDAO):

    constraint_to_column_map = dict(
        auth_tenant_name_key='name',
    )
    search_filter = SearchFilter(Tenant.name)
    column_map = dict(
        name=Tenant.name,
    )

    def exists(self, tenant_uuid):
        return self.count(uuid=tenant_uuid) > 0

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
            strict_filter = _UserDAO._new_strict_filter(**kwargs)
            search_filter = _UserDAO.new_search_filter(**kwargs)
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
            return s.query(TenantUser).filter(filter_).delete()

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


class _TokenDAO(BaseDAO):

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


class _UserDAO(_PaginatorMixin, BaseDAO):

    constraint_to_column_map = dict(
        auth_user_pkey='uuid',
        auth_user_username_key='username',
        auth_email_address_key='email_address',
    )
    search_filter = SearchFilter(User.username, Email.address)
    column_map = dict(
        username=User.username,
    )

    @staticmethod
    def _new_strict_filter(uuid=None, username=None, email_address=None, tenant_uuid=None,
                           group_uuid=None, **ignored):
        filter_ = text('true')
        if uuid:
            filter_ = and_(filter_, User.uuid == str(uuid))
        if username:
            filter_ = and_(filter_, User.username == username)
        if email_address:
            filter_ = and_(filter_, Email.address == email_address)
        if tenant_uuid:
            filter_ = and_(filter_, TenantUser.tenant_uuid == str(tenant_uuid))
        if group_uuid:
            filter_ = and_(filter_, UserGroup.group_uuid == str(group_uuid))
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

    def change_password(self, user_uuid, salt, hash_):
        filter_ = User.uuid == str(user_uuid)
        values = dict(
            password_salt=salt,
            password_hash=hash_,
        )

        with self.new_session() as s:
            s.query(User).filter(filter_).update(values)

    def exists(self, user_uuid):
        return self.count(uuid=user_uuid) > 0

    def remove_policy(self, user_uuid, policy_uuid):
        filter_ = and_(
            UserPolicy.user_uuid == user_uuid,
            UserPolicy.policy_uuid == policy_uuid,
        )

        with self.new_session() as s:
            return s.query(UserPolicy).filter(filter_).delete()

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

    def count_groups(self, user_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = _GroupDAO._new_strict_filter(**kwargs)
            search_filter = _GroupDAO.new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, UserGroup.user_uuid == str(user_uuid))

        with self.new_session() as s:
            return s.query(Group).join(UserGroup).filter(filter_).count()

    def count_policies(self, user_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = _PolicyDAO._new_strict_filter(**kwargs)
            search_filter = _PolicyDAO.new_search_filter(**kwargs)
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
            strict_filter = _TenantDAO._new_strict_filter(**kwargs)
            search_filter = _TenantDAO.new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, TenantUser.user_uuid == str(user_uuid))

        with self.new_session() as s:
            return s.query(Tenant).join(TenantUser).filter(filter_).count()

    def create(self, username, email_address, **kwargs):
        user_args = dict(
            username=username,
            password_hash=kwargs.get('hash_'),
            password_salt=kwargs.get('salt'),
        )
        uuid = kwargs.get('uuid')
        if uuid:
            user_args['uuid'] = str(uuid)

        email_confirmed = kwargs.get('email_confirmed', False)
        email_args = dict(address=email_address, confirmed=email_confirmed)

        with self.new_session() as s:
            try:
                email = Email(**email_args)
                user = User(**user_args)
                s.add_all([user, email])
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

            return dict(
                uuid=user.uuid,
                username=username,
                emails=[{'address': email_address, 'confirmed': email_confirmed, 'main': True}],
            )

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
            ).outerjoin(TenantUser).outerjoin(UserGroup).filter(filter_)
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
