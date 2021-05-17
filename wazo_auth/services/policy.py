# Copyright 2018-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService


class PolicyService(BaseService):
    def add_access(self, policy_uuid, access, scoping_tenant_uuid):
        self._assert_in_tenant_subtree(policy_uuid, scoping_tenant_uuid)
        self._dao.policy.associate_access(policy_uuid, access)

    def assert_policy_in_subtenant(self, scoping_tenant_uuid, uuid):
        tenant_uuids = self._tenant_tree.list_visible_tenants(scoping_tenant_uuid)
        exists = self._dao.policy.exists(uuid, tenant_uuids=tenant_uuids)
        if not exists:
            raise exceptions.UnknownPolicyException(uuid)

    def create(self, **kwargs):
        policy_uuid = self._dao.policy.create(**kwargs)
        return self._dao.policy.list_(uuid=policy_uuid, limit=1)[0]

    def count(self, scoping_tenant_uuid=None, **kwargs):
        if scoping_tenant_uuid:
            recurse = kwargs.get('recurse')
            if recurse:
                kwargs['tenant_uuids'] = self._tenant_tree.list_visible_tenants(
                    scoping_tenant_uuid
                )
            else:
                kwargs['tenant_uuids'] = [scoping_tenant_uuid]

        return self._dao.policy.count(**kwargs)

    def delete(self, policy_uuid, scoping_tenant_uuid):
        args = {}
        if scoping_tenant_uuid:
            args['tenant_uuids'] = self._tenant_tree.list_visible_tenants(
                scoping_tenant_uuid
            )

        policy = self._dao.policy.find_by(uuid=policy_uuid)
        if policy and policy.config_managed:
            raise exceptions.ReadOnlyPolicyException(policy_uuid)

        return self._dao.policy.delete(policy_uuid, **args)

    def delete_access(self, policy_uuid, access, scoping_tenant_uuid):
        self._assert_in_tenant_subtree(policy_uuid, scoping_tenant_uuid)
        self._dao.policy.dissociate_access(policy_uuid, access)

    def get(self, policy_uuid, scoping_tenant_uuid):
        tenant_uuids = self._tenant_tree.list_visible_tenants(scoping_tenant_uuid)
        return self._dao.policy.get(tenant_uuids, policy_uuid)

    def list(self, scoping_tenant_uuid=None, recurse=False, **kwargs):
        if scoping_tenant_uuid:
            kwargs['tenant_uuids'] = self._get_scoped_tenant_uuids(
                scoping_tenant_uuid, recurse
            )

        return self._dao.policy.list_(**kwargs)

    def list_tenants(self, policy_uuid, **kwargs):
        return self._dao.tenant.list_(policy_uuid=policy_uuid, **kwargs)

    def update(self, policy_uuid, scoping_tenant_uuid=None, **body):
        args = dict(body)
        if scoping_tenant_uuid:
            args['tenant_uuids'] = self._tenant_tree.list_visible_tenants(
                scoping_tenant_uuid
            )

        policy = self._dao.policy.find_by(uuid=policy_uuid)
        if policy and policy.config_managed:
            raise exceptions.ReadOnlyPolicyException(policy_uuid)

        self._dao.policy.update(policy_uuid, **args)
        return self._dao.policy.list_(uuid=policy_uuid, limit=1)[0]

    def _assert_in_tenant_subtree(self, policy_uuid, scoping_tenant_uuid):
        if not scoping_tenant_uuid:
            return
        tenant_uuids = self._tenant_tree.list_visible_tenants(scoping_tenant_uuid)
        self._dao.policy.get(tenant_uuids, policy_uuid)
