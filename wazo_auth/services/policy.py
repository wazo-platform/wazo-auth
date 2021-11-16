# Copyright 2018-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService


class PolicyService(BaseService):
    def add_access(self, policy_uuid, access, tenant_uuids):
        self._assert_in_tenant_subtree(policy_uuid, tenant_uuids)
        self._dao.policy.associate_access(policy_uuid, access)

    def create(self, **kwargs):
        policy_uuid = self._dao.policy.create(**kwargs)
        return self._dao.policy.find_by(uuid=policy_uuid)

    def count(self, **kwargs):
        return self._dao.policy.count(**kwargs)

    def delete(self, policy_uuid, tenant_uuids):
        policy = self._dao.policy.find_by(uuid=policy_uuid)
        if policy:
            if policy.config_managed:
                raise exceptions.ReadOnlyPolicyException(policy_uuid)

            if policy.shared and policy.tenant_uuid not in tenant_uuids:
                raise exceptions.ReadOnlyPolicyException(policy_uuid)

        return self._dao.policy.delete(policy_uuid, tenant_uuids=tenant_uuids)

    def delete_access(self, policy_uuid, access, tenant_uuids):
        self._assert_in_tenant_subtree(policy_uuid, tenant_uuids)
        self._dao.policy.dissociate_access(policy_uuid, access)

    def get(self, policy_uuid, tenant_uuids):
        return self._dao.policy.get(policy_uuid, tenant_uuids=tenant_uuids)

    def get_by_slug(self, policy_slug, tenant_uuids):
        return self._dao.policy.get_by(slug=policy_slug, tenant_uuids=tenant_uuids)

    def list(self, **kwargs):
        return self._dao.policy.list_(**kwargs)

    def list_tenants(self, policy_uuid, **kwargs):
        return self._dao.tenant.list_(policy_uuid=policy_uuid, **kwargs)

    def update(self, policy_uuid, tenant_uuids, **body):
        policy = self._dao.policy.find_by(uuid=policy_uuid)
        if policy:
            if policy.config_managed:
                raise exceptions.ReadOnlyPolicyException(policy_uuid)

            if policy.shared and policy.tenant_uuid not in tenant_uuids:
                raise exceptions.ReadOnlyPolicyException(policy_uuid)

        self._dao.policy.update(policy_uuid, tenant_uuids=tenant_uuids, **body)
        return self._dao.policy.find_by(uuid=policy_uuid, tenant_uuids=tenant_uuids)

    def _assert_in_tenant_subtree(self, policy_uuid, tenant_uuids):
        self._dao.policy.get(policy_uuid, tenant_uuids=tenant_uuids)
