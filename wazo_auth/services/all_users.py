# Copyright 2020-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from collections import defaultdict

from wazo_auth.database.helpers import commit_or_rollback

logger = logging.getLogger(__name__)


class AllUsersService:
    def __init__(self, dao, all_users_policies):
        self._dao = dao
        self._all_users_policies = all_users_policies

    def update_policies(self, tenant_uuids):
        logger.debug(
            'all_users: found %s policies to apply to all users of %s tenants',
            len(self._all_users_policies),
            len(tenant_uuids),
        )
        existing_config_managed_policies_by_tenant = defaultdict(list)
        for policy in self._dao.policy.list_(read_only=True):
            existing_config_managed_policies_by_tenant[policy.tenant_uuid].append(
                policy
            )

        policies = self.find_policies()
        current_group_policy_associations = (
            self._dao.group.get_all_policy_associations()
        )
        for tenant_uuid in tenant_uuids:
            self.associate_policies_for_tenant(
                tenant_uuid,
                policies,
                current_group_policy_associations,
                existing_config_managed_policies_by_tenant,
            )

        commit_or_rollback()

    def find_policies(self):
        policies = []
        for slug, enabled in self._all_users_policies.items():
            if not enabled:
                logger.debug('all_users: policy disabled: %s', slug)
                continue

            policy = self._dao.policy.find_by(slug=slug)
            if not policy:
                logger.error('all_users: Unable to found policy: %s', slug)
                continue
            policies.append(policy)

        return policies

    def associate_policies_for_tenant(
        self,
        tenant_uuid,
        policies,
        current_group_policy_associations,
        existing_config_managed_policies_by_tenant,
    ):
        all_users_group = self._dao.group.get_all_users_group(tenant_uuid)
        for policy in policies:
            if (all_users_group.uuid, policy.uuid) in current_group_policy_associations:
                continue
            self._associate_policy(tenant_uuid, policy.uuid, all_users_group.uuid)
            current_group_policy_associations.add((all_users_group.uuid, policy.uuid))

        existing_config_managed_policies = (
            existing_config_managed_policies_by_tenant.get(tenant_uuid) or []
        )
        policies_to_dissociate = [
            policy
            for policy in existing_config_managed_policies
            if policy.config_managed and policy.slug not in self._all_users_policies
        ]
        for policy in policies_to_dissociate:
            self._dissociate_policy(tenant_uuid, policy.uuid, all_users_group.uuid)

    def _associate_policy(self, tenant_uuid, policy_uuid, group_uuid):
        logger.debug(
            'all_users: tenant %s: associating policy %s to group %s',
            tenant_uuid,
            policy_uuid,
            group_uuid,
        )
        self._dao.group.add_policy(group_uuid, policy_uuid)

    def _dissociate_policy(self, tenant_uuid, policy_uuid, group_uuid):
        logger.debug(
            'all_users: tenant %s: dissociating policy %s from group %s',
            tenant_uuid,
            policy_uuid,
            group_uuid,
        )
        self._dao.group.remove_policy(group_uuid, policy_uuid)
