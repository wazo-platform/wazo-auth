# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService


class PolicyService(BaseService):

    def add_acl_template(self, policy_uuid, acl_template, scoping_tenant_uuid):
        self._assert_in_tenant_subtree(policy_uuid, scoping_tenant_uuid)

        return self._dao.policy.associate_policy_template(policy_uuid, acl_template)

    def assert_policy_in_subtenant(self, scoping_tenant_uuid, uuid):
        tenant_uuids = self._tenant_tree.list_nodes(scoping_tenant_uuid)
        exists = self._dao.policy.exists(uuid, tenant_uuids=tenant_uuids)
        if not exists:
            raise exceptions.UnknownPolicyException(uuid)

    def create(self, **kwargs):
        return self._dao.policy.create(**kwargs)

    def count(self, scoping_tenant_uuid=None, **kwargs):
        if scoping_tenant_uuid:
            recurse = kwargs.get('recurse')
            if recurse:
                kwargs['tenant_uuids'] = self._tenant_tree.list_nodes(scoping_tenant_uuid)
            else:
                kwargs['tenant_uuids'] = [scoping_tenant_uuid]

        return self._dao.policy.count(**kwargs)

    def count_tenants(self, policy_uuid, **kwargs):
        return self._dao.policy.count_tenants(policy_uuid, **kwargs)

    def delete(self, policy_uuid, scoping_tenant_uuid):
        args = {}
        if scoping_tenant_uuid:
            args['tenant_uuids'] = self._tenant_tree.list_nodes(scoping_tenant_uuid)

        return self._dao.policy.delete(policy_uuid, **args)

    def delete_acl_template(self, policy_uuid, acl_template, scoping_tenant_uuid):
        self._assert_in_tenant_subtree(policy_uuid, scoping_tenant_uuid)

        nb_deleted = self._dao.policy.dissociate_policy_template(policy_uuid, acl_template)
        if nb_deleted:
            return

        if not self._dao.policy.exists(policy_uuid):
            raise exceptions.UnknownPolicyException(policy_uuid)

    def get(self, policy_uuid, scoping_tenant_uuid):
        args = {
            'uuid': policy_uuid,
            'tenant_uuids': self._tenant_tree.list_nodes(scoping_tenant_uuid),
        }

        matching_policies = self._dao.policy.get(**args)
        for policy in matching_policies:
            return policy

        raise exceptions.UnknownPolicyException(policy_uuid)

    def list(self, scoping_tenant_uuid=None, recurse=False, **kwargs):
        if scoping_tenant_uuid:
            kwargs['tenant_uuids'] = self._get_scoped_tenant_uuids(scoping_tenant_uuid, recurse)

        return self._dao.policy.get(**kwargs)

    def list_tenants(self, policy_uuid, **kwargs):
        return self._dao.tenant.list_(policy_uuid=policy_uuid, **kwargs)

    def update(self, policy_uuid, scoping_tenant_uuid=None, **body):
        args = dict(body)
        if scoping_tenant_uuid:
            args['tenant_uuids'] = self._tenant_tree.list_nodes(scoping_tenant_uuid)

        self._dao.policy.update(policy_uuid, **args)
        return dict(uuid=policy_uuid, **body)

    def _assert_in_tenant_subtree(self, policy_uuid, scoping_tenant_uuid):
        if not scoping_tenant_uuid:
            return

        visible_tenant_uuids = self._tenant_tree.list_nodes(scoping_tenant_uuid)
        matching_policies = self._dao.policy.get(uuid=policy_uuid, tenant_uuids=visible_tenant_uuids)
        if not matching_policies:
            raise exceptions.UnknownPolicyException(policy_uuid)
