# Copyright 2020-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from wazo_auth.database.helpers import commit_or_rollback

logger = logging.getLogger(__name__)


class AllUsersService:
    def __init__(
        self,
        group_service,
        policy_service,
        tenant_service,
        default_policies,
        all_users_policies,
    ):
        self._group_service = group_service
        self._policy_service = policy_service
        self._tenant_service = tenant_service
        self._default_policies = default_policies
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
        existing_policy_slugs = {p['slug']: p['uuid'] for p in existing_policies}
        associated_policies = self._group_service.list_policies(all_users_group['uuid'])
        associated_policy_slugs = {p['slug']: p['uuid'] for p in associated_policies}
        for slug, policy in self._all_users_policies.items():
            if slug in associated_policy_slugs:
                associated_policy_uuid = associated_policy_slugs[slug]
                self._update_policy(
                    tenant_uuid,
                    associated_policy_uuid,
                    slug,
                    policy,
                    all_users_group,
                )
            elif slug in existing_policy_slugs:
                existing_policy_uuid = existing_policy_slugs[slug]
                self._update_policy(
                    tenant_uuid,
                    existing_policy_uuid,
                    slug,
                    policy,
                    all_users_group,
                )
                self._associate_policy(
                    tenant_uuid,
                    existing_policy_uuid,
                    all_users_group,
                )
            else:
                policy = self._create_policy(tenant_uuid, slug, policy, all_users_group)
                self._associate_policy(tenant_uuid, policy['uuid'], all_users_group)

        managed_policies = {**self._default_policies, **self._all_users_policies}
        policies_to_remove = [
            policy
            for policy in existing_policies
            if policy['config_managed'] and policy['slug'] not in managed_policies
        ]
        for policy in policies_to_remove:
            self._delete_policy(tenant_uuid, policy['uuid'])

    def _create_policy(self, tenant_uuid, slug, policy, all_users_group):
        logger.debug('all_users: tenant %s: creating policy %s', tenant_uuid, slug)
        return self._policy_service.create(
            name=slug,
            slug=slug,
            tenant_uuid=tenant_uuid,
            description='Automatically created to be applied to all users',
            config_managed=True,
            **policy,
        )

    def _update_policy(
        self, tenant_uuid, policy_uuid, policy_slug, policy, all_users_group
    ):
        logger.debug(
            'all_users: tenant %s: updating policy %s', tenant_uuid, policy_uuid
        )
        self._policy_service.update(
            policy_uuid,
            name=policy_slug,
            description='Automatically created to be applied to all users',
            config_managed=True,
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

    def _delete_policy(self, tenant_uuid, policy_uuid):
        logger.debug(
            'all_users: tenant %s: deleting policy %s',
            tenant_uuid,
            policy_uuid,
        )
        self._policy_service.delete(policy_uuid, tenant_uuid)
