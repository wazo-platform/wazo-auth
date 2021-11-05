# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import random
import re
import string
from sqlalchemy import (
    and_,
    exc,
    or_,
)
from .base import BaseDAO, PaginatorMixin
from . import filters
from ..models import (
    Access,
    GroupPolicy,
    Policy,
    PolicyAccess,
    Tenant,
    UserPolicy,
)
from ... import exceptions

MAX_SLUG_LEN = 80
SLUG_LEN = 3


class PolicyDAO(filters.FilterMixin, PaginatorMixin, BaseDAO):

    search_filter = filters.policy_search_filter
    strict_filter = filters.policy_strict_filter
    column_map = {
        'name': Policy.name,
        'slug': Policy.slug,
        'description': Policy.description,
        'uuid': Policy.uuid,
    }

    def associate_access(self, policy_uuid, access):
        self._associate_acl(policy_uuid, [access])
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                raise exceptions.DuplicateAccessException(access)
            if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                constraint = e.orig.diag.constraint_name
                if constraint == 'auth_policy_access_policy_uuid_fkey':
                    raise exceptions.UnknownPolicyException(policy_uuid)
            raise

    def dissociate_access(self, policy_uuid, access):
        filter_ = and_(
            Access.access == access,
            PolicyAccess.policy_uuid == str(policy_uuid),
        )

        query = self.session.query(Access.id_).join(PolicyAccess).filter(filter_)
        access_id = query.first()

        filter_ = and_(
            PolicyAccess.policy_uuid == str(policy_uuid),
            PolicyAccess.access_id == access_id,
        )
        self.session.query(PolicyAccess).filter(filter_).delete()
        self.session.flush()

    def count(self, search, tenant_uuids=None, **ignored):
        filter_ = self.new_search_filter(search=search)

        if tenant_uuids is not None:
            requested_tenant_uuid = self._extract_requested_tenant_uuid(tenant_uuids)
            filter_ = and_(
                filter_,
                or_(
                    Policy.tenant_uuid.in_(tenant_uuids),
                    self._read_only_filter(requested_tenant_uuid),
                ),
            )

        return self.session.query(Policy).filter(filter_).count()

    def create(
        self,
        name,
        slug,
        description,
        acl,
        tenant_uuid,
        config_managed=False,
        shared=False,
    ):
        if not slug:
            slug = self._generate_slug(name)

        policy = Policy(
            name=name,
            slug=slug,
            description=description,
            config_managed=config_managed,
            shared=shared,
            tenant_uuid=tenant_uuid,
        )
        self._check_duplicate_policy(policy)

        self.session.add(policy)
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                raise exceptions.DuplicatePolicyException(name)
            raise
        self._associate_acl(policy.uuid, acl)
        self.session.flush()
        return policy.uuid

    def _check_duplicate_policy(self, policy):
        tenant_uuids = self._reverse_tenant_tree_query(policy.tenant_uuid)
        filter_ = and_(
            Policy.tenant_uuid.in_(tenant_uuids),
            Policy.shared.is_(True),
            or_(Policy.slug == policy.slug, Policy.name == policy.name),
        )
        result = self.session.query(Policy).filter(filter_).first()
        if result:
            raise exceptions.DuplicatePolicyException(policy.name)

        if policy.shared:
            tenant_uuids = self._tenant_tree_query(policy.tenant_uuid)
            filter_ = and_(
                Policy.tenant_uuid.in_(tenant_uuids),
                or_(Policy.slug == policy.slug, Policy.name == policy.name),
            )
            result = self.session.query(Policy).filter(filter_).first()
            if result:
                raise exceptions.DuplicatePolicyException(policy.name)

    def delete(self, policy_uuid, tenant_uuids):
        filter_ = Policy.uuid == str(policy_uuid)
        if tenant_uuids is not None:
            filter_ = and_(filter_, Policy.tenant_uuid.in_(tenant_uuids))

        nb_deleted = (
            self.session.query(Policy).filter(filter_).delete(synchronize_session=False)
        )
        self.session.flush()
        if not nb_deleted:
            raise exceptions.UnknownPolicyException(policy_uuid)

    def exists(self, policy_uuid, tenant_uuids=None):
        filter_ = Policy.uuid == str(policy_uuid)

        if tenant_uuids is not None:
            if not tenant_uuids:
                return False

            filter_ = and_(filter_, Policy.tenant_uuid.in_(tenant_uuids))

        result = self.session.query(Policy).filter(filter_).count() > 0
        self.session.flush()
        return result

    def _is_associated_user(self, uuid):
        query = self.session.query(Policy).join(UserPolicy).filter(Policy.uuid == uuid)
        return query.count() > 0

    def _is_associated_group(self, uuid):
        query = self.session.query(Policy).join(GroupPolicy).filter(Policy.uuid == uuid)
        return query.count() > 0

    def is_associated(self, uuid):
        return self._is_associated_user(uuid) or self._is_associated_group(uuid)

    def list_(self, tenant_uuids=None, **kwargs):
        strict_filter = self.new_strict_filter(**kwargs)
        search_filter = self.new_search_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        read_only = kwargs.get('read_only')
        read_only_filter = ''
        if tenant_uuids is not None:
            requested_tenant_uuid = self._extract_requested_tenant_uuid(tenant_uuids)
            if read_only is True:
                parent_owner_uuid = (
                    self.session.query(Tenant.parent_uuid)
                    .filter(Tenant.uuid == requested_tenant_uuid)
                    .first()
                )
                read_only_filter = self._read_only_filter(parent_owner_uuid)
            elif read_only is False:
                tenant_filter = Policy.tenant_uuid.in_(tenant_uuids)
                read_only_filter = and_(tenant_filter, read_only_filter)
            elif read_only is None:
                read_only_filter = or_(
                    Policy.tenant_uuid.in_(tenant_uuids),
                    self._read_only_filter(requested_tenant_uuid),
                )
        else:
            if read_only is True:
                read_only_filter = Policy.config_managed.is_(True)
            elif read_only is False:
                read_only_filter = Policy.config_managed.is_(False)

        filter_ = and_(filter_, read_only_filter)

        query = (
            self.session.query(Policy)
            .outerjoin(UserPolicy)
            .outerjoin(GroupPolicy)
            .filter(filter_)
            .group_by(Policy)
        )
        query = self._paginator.update_query(query, **kwargs)

        policies = query.all()
        for policy in policies:
            self._set_tenant_uuid_exposed(policy, tenant_uuids)
            self._set_read_only(policy)
            self._set_shared_exposed(policy)
        return policies

    def list_without_relations(self, **kwargs):
        if 'read_only' in kwargs:
            raise NotImplementedError('read_only filter')
        if 'tenant_uuid_exposed' in kwargs:
            raise NotImplementedError('tenant_uuid_exposed filter')
        if 'shared_exposed' in kwargs:
            raise NotImplementedError('shared_exposed filter')

        tenant_uuid = kwargs.pop('tenant_uuid', None)

        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self.new_strict_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        if tenant_uuid:
            tenant_uuid = str(tenant_uuid)
            read_only_filter = or_(
                Policy.tenant_uuid == tenant_uuid,
                self._read_only_filter(tenant_uuid),
            )
            filter_ = and_(filter_, read_only_filter)

        query = self.session.query(Policy).filter(filter_).group_by(Policy)
        query = self._paginator.update_query(query, **kwargs)
        policies = query.all()
        tenant_uuids = [tenant_uuid] if tenant_uuid else None
        for policy in policies:
            self._set_tenant_uuid_exposed(policy, tenant_uuids)
            self._set_read_only(policy)
            self._set_shared_exposed(policy)
        return policies

    def _read_only_filter(self, tenant_uuid):
        filter_ = Policy.config_managed.is_(True)
        tenant_branch_query = self._reverse_tenant_tree_query(tenant_uuid)
        shared_filter = and_(
            Policy.shared.is_(True),
            Policy.tenant_uuid.in_(tenant_branch_query),
        )
        filter_ = or_(filter_, shared_filter)
        return filter_

    def _reverse_tenant_tree_query(self, bottom_tenant_uuid):
        top_tenant_uuid = self._find_top_tenant().uuid
        if bottom_tenant_uuid == top_tenant_uuid:
            filter_ = Tenant.uuid == top_tenant_uuid
            return self.session.query(Tenant.uuid).filter(filter_)

        included_tenants = (
            self.session.query(Tenant.parent_uuid, Tenant.uuid)
            .filter(
                or_(
                    Tenant.uuid == str(bottom_tenant_uuid),
                    Tenant.uuid == top_tenant_uuid,
                )
            )
            .cte(recursive=True)
        )
        included_tenants = included_tenants.union_all(
            self.session.query(Tenant.parent_uuid, Tenant.uuid).filter(
                and_(
                    Tenant.uuid == included_tenants.c.parent_uuid,
                    Tenant.parent_uuid != Tenant.uuid,
                )
            )
        )
        return (
            self.session.query(Tenant.uuid)
            .select_from(included_tenants)
            .join(Tenant, Tenant.uuid == included_tenants.c.uuid)
        )

    def _find_top_tenant(self):
        query = self.session.query(Tenant).filter(Tenant.uuid == Tenant.parent_uuid)
        return query.first()

    def _tenant_tree_query(self, scoping_tenant_uuid):
        top_tenant_uuid = self._find_top_tenant()
        if scoping_tenant_uuid == top_tenant_uuid:
            return self.session.query(Tenant.uuid)

        included_tenants = (
            self.session.query(Tenant.uuid, Tenant.parent_uuid)
            .filter(Tenant.uuid == str(scoping_tenant_uuid))
            .cte(recursive=True)
        )
        included_tenants = included_tenants.union_all(
            self.session.query(Tenant.uuid, Tenant.parent_uuid).filter(
                and_(
                    Tenant.parent_uuid == included_tenants.c.uuid,
                    Tenant.uuid != Tenant.parent_uuid,
                )
            )
        )
        return (
            self.session.query(Tenant.uuid)
            .select_from(included_tenants)
            .join(Tenant, Tenant.uuid == included_tenants.c.uuid)
        )

    def _set_tenant_uuid_exposed(self, policy, tenant_uuids):
        tenant_uuid = policy.tenant_uuid
        if not tenant_uuids:
            policy.tenant_uuid_exposed = tenant_uuid
            return

        if policy.config_managed or policy.shared:
            if tenant_uuid not in tenant_uuids:
                tenant_uuid = tenant_uuids[0]

        policy.tenant_uuid_exposed = tenant_uuid

    def _set_read_only(self, policy):
        if policy.config_managed:
            policy.read_only = True
            return

        if policy.shared and policy.tenant_uuid_exposed != policy.tenant_uuid:
            policy.read_only = True
            return

        policy.read_only = False

    def _set_shared_exposed(self, policy):
        if policy.shared and policy.tenant_uuid_exposed != policy.tenant_uuid:
            policy.shared_exposed = False
            return

        policy.shared_exposed = policy.shared

    def get(self, policy_uuid, tenant_uuids=None):
        return self._get_by(uuid=str(policy_uuid), tenant_uuids=tenant_uuids)

    def get_by(self, tenant_uuids=None, **kwargs):
        return self._get_by(tenant_uuids=tenant_uuids, **kwargs)

    def _get_by(self, tenant_uuids=None, **kwargs):
        if 'read_only' in kwargs:
            raise NotImplementedError('read_only filter')
        if 'tenant_uuid_exposed' in kwargs:
            raise NotImplementedError('tenant_uuid_exposed filter')
        if 'shared_exposed' in kwargs:
            raise NotImplementedError('shared_exposed filter')

        filter_ = self.new_strict_filter(**kwargs)
        query = self.session.query(Policy).filter(filter_)
        if tenant_uuids is not None:
            requested_tenant_uuid = self._extract_requested_tenant_uuid(tenant_uuids)
            read_only_filter = or_(
                Policy.tenant_uuid.in_(tenant_uuids),
                self._read_only_filter(requested_tenant_uuid),
            )
            query = query.filter(read_only_filter)
        policy = query.first()

        if not policy:
            raise exceptions.UnknownPolicyException(kwargs)

        self._set_tenant_uuid_exposed(policy, tenant_uuids)
        self._set_read_only(policy)
        self._set_shared_exposed(policy)
        return policy

    def find_by(self, **kwargs):
        if 'read_only' in kwargs:
            raise NotImplementedError('read_only filter')
        if 'tenant_uuid_exposed' in kwargs:
            raise NotImplementedError('tenant_uuid_exposed filter')
        if 'shared_exposed' in kwargs:
            raise NotImplementedError('shared_exposed filter')

        filter_ = self.new_strict_filter(**kwargs)
        query = self.session.query(Policy).filter(filter_)
        policy = query.first()
        if policy:
            self._set_tenant_uuid_exposed(policy, tenant_uuids=None)
            self._set_read_only(policy)
            self._set_shared_exposed(policy)

            # NOTE(fblackburn): di/association policy/access
            # don't use relationship and object is not updated
            self.session.expire(policy, ['accesses'])
        return policy

    def update(
        self,
        policy_uuid,
        name,
        description,
        acl,
        config_managed=None,
        tenant_uuids=None,
    ):
        filter_ = Policy.uuid == str(policy_uuid)
        if tenant_uuids is not None:
            filter_ = and_(filter_, Policy.tenant_uuid.in_(tenant_uuids))

        body = {
            'name': name,
            'description': description,
        }
        if config_managed is not None:
            body['config_managed'] = config_managed

        affected_rows = (
            self.session.query(Policy)
            .filter(filter_)
            .update(body, synchronize_session='fetch')
        )
        if not affected_rows:
            raise exceptions.UnknownPolicyException(policy_uuid)

        try:
            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                raise exceptions.DuplicatePolicyException(name)
            raise

        self._dissociate_all_acl(policy_uuid)
        self._associate_acl(policy_uuid, acl)
        self.session.flush()

    def _associate_acl(self, policy_uuid, acl):
        ids = self._create_or_find_acl(acl)
        access_policies = [
            PolicyAccess(policy_uuid=str(policy_uuid), access_id=id_) for id_ in ids
        ]
        self.session.add_all(access_policies)

    def _create_or_find_acl(self, acl):
        if not acl:
            return []

        accesses = self.session.query(Access).filter(Access.access.in_(acl)).all()
        existing = {access.access: access.id_ for access in accesses}
        for access in acl:
            if access in existing:
                continue
            id_ = self._insert_access(access)
            existing[access] = id_
        result = existing.values()
        self.session.flush()
        return result

    def _dissociate_all_acl(self, policy_uuid):
        filter_ = PolicyAccess.policy_uuid == str(policy_uuid)
        self.session.query(PolicyAccess).filter(filter_).delete()
        self.session.flush()

    def _insert_access(self, access):
        tpl = Access(access=access)
        self.session.add(tpl)
        self.session.flush()
        return tpl.id_

    def _generate_slug(self, name):
        if name:
            slug = _slug_from_name(name)
            if not self._slug_exist(slug):
                return slug

        while True:
            slug = _generate_random_name(SLUG_LEN)
            if not self._slug_exist(slug):
                return slug

    def _slug_exist(self, slug):
        return self.session.query(Policy.slug).filter(Policy.slug == slug).count() > 0

    def _extract_requested_tenant_uuid(self, tenant_uuids):
        # NOTE(fblackburn): We rely on implementation detail about tenant_uuids generation to
        # extract requested tenant_uuid. A better solution would be to stop extracting tenant_uuids
        # from http layer and only pass requested_tenant_uuid, only for policy resource
        if not tenant_uuids:
            raise Exception(f'Cannot extract requested tenant from "{tenant_uuids}"')
        return tenant_uuids[0]


def _slug_from_name(name):
    return re.sub(r'[^a-zA-Z0-9_-]', '', name)[:MAX_SLUG_LEN]


def _generate_random_name(length):
    choices = string.ascii_lowercase + string.digits
    return ''.join(random.choice(choices) for _ in range(length))
