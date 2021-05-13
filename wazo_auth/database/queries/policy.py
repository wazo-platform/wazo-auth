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
    PolicyAccess,
    GroupPolicy,
    Policy,
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
            PolicyAccess.policy_uuid == policy_uuid,
        )

        query = self.session.query(Access.id_).join(PolicyAccess).filter(filter_)
        access_id = query.first()

        filter_ = and_(
            PolicyAccess.policy_uuid == policy_uuid,
            PolicyAccess.access_id == access_id,
        )
        self.session.query(PolicyAccess).filter(filter_).delete()
        self.session.flush()

    def count(self, search, tenant_uuids=None, **ignored):
        filter_ = self.new_search_filter(search=search)

        if tenant_uuids is not None:
            filter_ = and_(
                filter_,
                or_(
                    Policy.tenant_uuid.in_(tenant_uuids),
                    Policy.config_managed.is_(True),
                ),
            )

        return self.session.query(Policy).filter(filter_).count()

    def create(self, name, slug, description, acl, config_managed, tenant_uuid):

        if not slug:
            slug = self._generate_slug(name)

        policy = Policy(
            name=name,
            slug=slug,
            description=description,
            config_managed=config_managed,
            tenant_uuid=tenant_uuid,
        )
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

    def delete(self, policy_uuid, tenant_uuids):
        filter_ = Policy.uuid == policy_uuid
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

    def is_associated_user(self, uuid):
        query = self.session.query(Policy).join(UserPolicy).filter(Policy.uuid == uuid)
        return query.count() > 0

    def is_associated_group(self, uuid):
        query = self.session.query(Policy).join(GroupPolicy).filter(Policy.uuid == uuid)
        return query.count() > 0

    def list_(self, tenant_uuids=None, **kwargs):
        strict_filter = self.new_strict_filter(**kwargs)
        search_filter = self.new_search_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        if tenant_uuids is not None:
            read_only = kwargs.get('read_only')
            if read_only is True:
                managed_filter = Policy.config_managed.is_(True)
            elif read_only is False:
                managed_filter = Policy.tenant_uuid.in_(tenant_uuids)
            else:
                managed_filter = or_(
                    Policy.tenant_uuid.in_(tenant_uuids),
                    Policy.config_managed.is_(True),
                )
            filter_ = and_(filter_, managed_filter)

        query = (
            self.session.query(Policy)
            .outerjoin(PolicyAccess)
            .outerjoin(Access)
            .outerjoin(UserPolicy)
            .outerjoin(GroupPolicy)
            .filter(filter_)
        )
        query = self._paginator.update_query(query, **kwargs)

        policies = query.all()
        for policy in policies:
            tenant_uuid = policy.tenant_uuid
            if policy.config_managed:
                if tenant_uuids and tenant_uuid not in tenant_uuids:
                    tenant_uuid = tenant_uuids[0]
            policy.tenant_uuid_exposed = tenant_uuid
        return policies

    def list_without_relations(self, **kwargs):
        tenant_uuid = kwargs.pop('tenant_uuid', None)
        if tenant_uuid:
            tenant_uuid = str(tenant_uuid)
            tenant_filter = or_(
                Policy.tenant_uuid == tenant_uuid,
                Policy.config_managed.is_(True),
            )

        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self.new_strict_filter(**kwargs)
        filter_ = and_(tenant_filter, strict_filter, search_filter)

        query = self.session.query(Policy).filter(filter_).group_by(Policy)
        query = self._paginator.update_query(query, **kwargs)
        policies = query.all()
        for policy in policies:
            self._set_tenant_uuid_exposed(policy, tenant_uuid)
        return policies

    def _set_tenant_uuid_exposed(self, policy, requested_tenant_uuid):
        policy.tenant_uuid_exposed = requested_tenant_uuid or policy.tenant_uuid

    def get(self, tenant_uuids, policy_uuid):
        query = (
            self.session.query(Policy)
            .filter(Policy.uuid == policy_uuid)
            .filter(
                or_(
                    Policy.tenant_uuid.in_(tenant_uuids),
                    Policy.config_managed.is_(True),
                )
            )
        )
        policy = query.first()
        if not policy:
            raise exceptions.UnknownPolicyException(policy_uuid)
        return policy

    def find_by(self, **kwargs):
        filter_ = self.new_strict_filter(**kwargs)
        query = self.session.query(Policy).filter(filter_)
        policy = query.first()
        if policy:
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
        config_managed,
        tenant_uuids=None,
    ):
        filter_ = Policy.uuid == policy_uuid
        if tenant_uuids is not None:
            filter_ = and_(filter_, Policy.tenant_uuid.in_(tenant_uuids))

        body = {
            'name': name,
            'description': description,
            'config_managed': config_managed,
        }
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
            PolicyAccess(policy_uuid=policy_uuid, access_id=id_) for id_ in ids
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
        filter_ = PolicyAccess.policy_uuid == policy_uuid
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


def _slug_from_name(name):
    return re.sub(r'[^a-zA-Z0-9_-]', '', name)[:MAX_SLUG_LEN]


def _generate_random_name(length):
    choices = string.ascii_lowercase + string.digits
    return ''.join(random.choice(choices) for _ in range(length))
