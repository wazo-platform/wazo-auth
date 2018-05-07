# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService


class PolicyService(BaseService):

    def __init__(self, dao, tenant_tree):
        super(PolicyService, self).__init__(dao)
        self._tenant_tree = tenant_tree

    def add_acl_template(self, policy_uuid, acl_template):
        return self._dao.policy.associate_policy_template(policy_uuid, acl_template)

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

    def delete(self, policy_uuid):
        return self._dao.policy.delete(policy_uuid)

    def delete_acl_template(self, policy_uuid, acl_template):
        nb_deleted = self._dao.policy.dissociate_policy_template(policy_uuid, acl_template)
        if nb_deleted:
            return

        if not self._dao.policy.exists(policy_uuid):
            raise exceptions.UnknownPolicyException(policy_uuid)

    def get(self, policy_uuid, scoping_tenant_uuid=None):
        args = {'uuid': policy_uuid}
        if scoping_tenant_uuid:
            args['tenant_uuids'] = [scoping_tenant_uuid]

        matching_policies = self._dao.policy.get(**args)
        for policy in matching_policies:
            return policy
        raise exceptions.UnknownPolicyException(policy_uuid)

    def list(self, scoping_tenant_uuid=None, **kwargs):
        if scoping_tenant_uuid:
            recurse = kwargs.get('recurse')
            if recurse:
                kwargs['tenant_uuids'] = self._tenant_tree.list_nodes(scoping_tenant_uuid)
            else:
                kwargs['tenant_uuids'] = [scoping_tenant_uuid]

        return self._dao.policy.get(**kwargs)

    def list_tenants(self, policy_uuid, **kwargs):
        return self._dao.tenant.list_(policy_uuid=policy_uuid, **kwargs)

    def update(self, policy_uuid, **body):
        self._dao.policy.update(policy_uuid, **body)
        return dict(uuid=policy_uuid, **body)
