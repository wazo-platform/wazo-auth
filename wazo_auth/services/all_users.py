# Copyright 2020-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from wazo_auth.database.helpers import commit_or_rollback

logger = logging.getLogger(__name__)


class AllUsersService:
    def __init__(self, dao, all_users_policies):
        self._dao = dao
        self._all_users_policies = all_users_policies

    def update_policies(self):
        top_tenant_uuid = self._dao.tenant.find_top_tenant()
        tenants = self._dao.tenant.list_visible_tenants(top_tenant_uuid)
        tenant_uuids = [tenant.uuid for tenant in tenants]
        logger.debug(
            'all_users: found %s policies to apply to all users of %s tenants',
            len(self._all_users_policies),
            len(tenants),
        )
        policies = self.find_policies()
        for tenant_uuid in tenant_uuids:
            self.associate_policies_for_tenant(tenant_uuid, policies)

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

    def associate_policies_for_tenant(self, tenant_uuid, policies):
        all_users_group = self._dao.group.get_all_users_group(tenant_uuid)
        for policy in policies:
            self._associate_policy(tenant_uuid, policy.uuid, all_users_group.uuid)

        existing_policies = self._dao.policy.list_(tenant_uuid=tenant_uuid)
        policies_to_dissociate = [
            policy
            for policy in existing_policies
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
