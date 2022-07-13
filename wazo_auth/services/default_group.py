# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from wazo_auth.database.helpers import commit_or_rollback

logger = logging.getLogger(__name__)


class DefaultGroupService:
    def __init__(self, dao, default_groups):
        self._dao = dao
        self._default_groups = default_groups

    def update_groups(self):
        logger.debug(
            'Found %s groups to apply in every tenant',
            len(self._default_groups),
        )
        top_tenant_uuid = self._dao.tenant.find_top_tenant()
        tenants = self._dao.tenant.list_visible_tenants(top_tenant_uuid)
        for tenant in tenants:
            self.update_groups_for_tenant(tenant.uuid)
        commit_or_rollback()

    def update_groups_for_tenant(self, tenant_uuid):
        for group_slug, group_args in self._default_groups.items():
            group = self._dao.group.find_by(name=group_slug, tenant_uuid=tenant_uuid)
            if group:
                self._update_group(tenant_uuid, group.uuid, group_slug, group_args)
            else:
                self._create_group(tenant_uuid, group_slug, group_args)

    def _create_group(self, tenant_uuid, group_slug, group):
        logger.debug('Tenant %s: creating group %s', tenant_uuid, group_slug)
        group = dict(group)
        policies = group.pop('policies', {})
        group_uuid = self._dao.group.create(
            name=group_slug,
            slug=group_slug,
            tenant_uuid=tenant_uuid,
            system_managed=False,
            **group,
        )
        enabled_policies = (
            policy_slug for policy_slug, enabled in policies.items() if enabled
        )
        for policy_slug in enabled_policies:
            logger.debug(
                'Tenant %s: adding policy %s to group %s',
                tenant_uuid,
                policy_slug,
                group_slug,
            )
            policy = self._dao.policy.find_by(slug=policy_slug)
            if not policy:
                logger.error(
                    'Tenant %s: Policy "%s" does not exist. '
                    'Skipping association with default group "%s"',
                    tenant_uuid,
                    policy_slug,
                    group_slug,
                )
                continue
            self._dao.group.add_policy(group_uuid, policy.uuid)

    def _update_group(self, tenant_uuid, group_uuid, group_slug, group):
        logger.debug('Tenant %s: updating group %s', tenant_uuid, group_slug)
        group = dict(group)
        policies = group.pop('policies', {})
        self._dao.group.update(
            group_uuid,
            name=group_slug,
            **group,
        )

        enabled_policies = (
            policy_slug for policy_slug, enabled in policies.items() if enabled
        )
        disabled_policies = (
            policy_slug for policy_slug, enabled in policies.items() if not enabled
        )
        existing_policies = (
            policy.slug for policy in self._dao.policy.list_(group_uuid=group_uuid)
        )
        policies_to_add = set(enabled_policies) - set(existing_policies)
        policies_to_remove = set(disabled_policies) & set(existing_policies)
        for policy_slug in policies_to_add:
            logger.debug(
                'Tenant %s: adding policy %s to group %s',
                tenant_uuid,
                policy_slug,
                group_slug,
            )
            policy = self._dao.policy.find_by(slug=policy_slug)
            if not policy:
                logger.error(
                    'Tenant %s: Policy "%s" does not exist. '
                    'Skipping association with default group "%s"',
                    tenant_uuid,
                    policy_slug,
                    group_slug,
                )
                continue
            self._dao.group.add_policy(group_uuid, policy.uuid)

        for policy_slug in policies_to_remove:
            logger.debug(
                'Tenant %s: removing policy %s from group %s',
                tenant_uuid,
                policy_slug,
                group_slug,
            )
            policy = self._dao.policy.find_by(slug=policy_slug)
            if not policy:
                logger.error(
                    'Tenant %s: Policy "%s" does not exist. '
                    'Skipping dissociation with default group "%s"',
                    tenant_uuid,
                    policy_slug,
                    group_slug,
                )
                continue
            self._dao.group.remove_policy(group_uuid, policy.uuid)
