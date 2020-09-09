# Copyright 2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from wazo_auth.database.helpers import commit_or_rollback

logger = logging.getLogger(__name__)


class AllUsersService:
    def __init__(
        self, group_service, policy_service, tenant_service, all_users_policies
    ):
        self._group_service = group_service
        self._policy_service = policy_service
        self._tenant_service = tenant_service
        self._all_users_policies = all_users_policies

    def update_policies(self):
        top_tenant_uuid = self._tenant_service.find_top_tenant()
        tenants = self._tenant_service.list_(top_tenant_uuid)
        tenant_uuids = [tenant['uuid'] for tenant in tenants]
        logger.debug(
            'all_users: found %s policies to apply to all users of %s tenants',
            len(self._all_users_policies),
            len(tenants),
        )
        for tenant_uuid in tenant_uuids:
            self.update_policies_for_tenant(tenant_uuid)

        commit_or_rollback()

    def update_policies_for_tenant(self, tenant_uuid):
        all_users_group = self._group_service.get_all_users_group(tenant_uuid)
        existing_policies = self._policy_service.list(scoping_tenant_uuid=tenant_uuid)
        existing_policy_names = {
            policy['name']: policy['uuid'] for policy in existing_policies
        }
        associated_policies = self._group_service.list_policies(all_users_group['uuid'])
        associated_policy_names = {
            policy['name']: policy['uuid'] for policy in associated_policies
        }
        for name, policy in self._all_users_policies.items():
            if name in associated_policy_names:
                associated_policy_uuid = associated_policy_names[name]
                self._update_policy(
                    tenant_uuid, associated_policy_uuid, name, policy, all_users_group
                )
            elif name in existing_policy_names:
                existing_policy_uuid = existing_policy_names[name]
                self._update_policy(
                    tenant_uuid, existing_policy_uuid, name, policy, all_users_group
                )
                self._associate_policy(
                    tenant_uuid, existing_policy_uuid, all_users_group
                )
            else:
                policy_uuid = self._create_policy(
                    tenant_uuid, name, policy, all_users_group
                )
                self._associate_policy(tenant_uuid, policy_uuid, all_users_group)

    def _create_policy(self, tenant_uuid, name, policy, all_users_group):
        logger.debug('all_users: tenant %s: creating policy %s', tenant_uuid, name)
        return self._policy_service.create(
            name=name,
            tenant_uuid=tenant_uuid,
            description='Automatically created to be applied to all users',
            **policy,
        )

    def _update_policy(
        self, tenant_uuid, policy_uuid, policy_name, policy, all_users_group
    ):
        logger.debug(
            'all_users: tenant %s: updating policy %s', tenant_uuid, policy_uuid
        )
        self._policy_service.update(
            policy_uuid,
            name=policy_name,
            description='Automatically created to be applied to all users',
            **policy,
        )

    def _associate_policy(self, tenant_uuid, policy_uuid, all_users_group):
        logger.debug(
            'all_users: tenant %s: associating policy %s to group %s',
            tenant_uuid,
            policy_uuid,
            all_users_group['uuid'],
        )
        self._group_service.add_policy(all_users_group['uuid'], policy_uuid)
