# Copyright 2018-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService


class PolicyService(BaseService):
    def add_access(self, policy_uuid, access, scoping_tenant_uuid):
        self._assert_in_tenant_subtree(policy_uuid, scoping_tenant_uuid)

        return self._dao.policy.associate_access(policy_uuid, access)

    def assert_policy_in_subtenant(self, scoping_tenant_uuid, uuid):
        tenant_uuids = self._tenant_tree.list_visible_tenants(scoping_tenant_uuid)
        exists = self._dao.policy.exists(uuid, tenant_uuids=tenant_uuids)
        if not exists:
            raise exceptions.UnknownPolicyException(uuid)

    def create(self, **kwargs):
        kwargs.setdefault('config_managed', False)
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

        policies = self._dao.policy.list_(tenant_uuids=None, uuid=policy_uuid, limit=1)
        if policies and policies[0]['config_managed']:
            raise exceptions.ReadOnlyPolicyException(policy_uuid)

        return self._dao.policy.delete(policy_uuid, **args)

    def delete_without_check(self, policy_uuid):
        return self._dao.policy.delete(policy_uuid, tenant_uuids=None)

    def delete_access(self, policy_uuid, access, scoping_tenant_uuid):
        self._assert_in_tenant_subtree(policy_uuid, scoping_tenant_uuid)

        nb_deleted = self._dao.policy.dissociate_access(policy_uuid, access)
        if nb_deleted:
            return

        if not self._dao.policy.exists(policy_uuid):
            raise exceptions.UnknownPolicyException(policy_uuid)

    def get(self, policy_uuid, scoping_tenant_uuid):
        args = {
            'uuid': policy_uuid,
            'tenant_uuids': self._tenant_tree.list_visible_tenants(scoping_tenant_uuid),
        }

        matching_policies = self._dao.policy.list_(**args)
        for policy in matching_policies:
            return policy

        raise exceptions.UnknownPolicyException(policy_uuid)

    def list(self, scoping_tenant_uuid=None, recurse=False, **kwargs):
        if scoping_tenant_uuid:
            kwargs['tenant_uuids'] = self._get_scoped_tenant_uuids(
                scoping_tenant_uuid, recurse
            )

        return self._dao.policy.list_(**kwargs)

    def list_tenants(self, policy_uuid, **kwargs):
        return self._dao.tenant.list_(policy_uuid=policy_uuid, **kwargs)

    def is_associated(self, policy_uuid):
        return self._dao.policy.is_associated_user(
            policy_uuid
        ) or self._dao.policy.is_associated_group(policy_uuid)

    def update(self, policy_uuid, scoping_tenant_uuid=None, **body):
        args = dict(body)
        args.setdefault('config_managed', False)
        if scoping_tenant_uuid:
            args['tenant_uuids'] = self._tenant_tree.list_visible_tenants(
                scoping_tenant_uuid
            )

        policies = self._dao.policy.list_(tenant_uuids=None, uuid=policy_uuid, limit=1)
        if not args['config_managed'] and policies and policies[0]['config_managed']:
            raise exceptions.ReadOnlyPolicyException(policy_uuid)

        self._dao.policy.update(policy_uuid, **args)
        return self._dao.policy.list_(uuid=policy_uuid, limit=1)[0]

    def _assert_in_tenant_subtree(self, policy_uuid, scoping_tenant_uuid):
        if not scoping_tenant_uuid:
            return

        visible_tenant_uuids = self._tenant_tree.list_visible_tenants(
            scoping_tenant_uuid
        )
        matching_policies = self._dao.policy.list_(
            uuid=policy_uuid, tenant_uuids=visible_tenant_uuids
        )
        if not matching_policies:
            raise exceptions.UnknownPolicyException(policy_uuid)
