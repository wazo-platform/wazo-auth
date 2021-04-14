# Copyright 2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from wazo_auth.database.helpers import commit_or_rollback

logger = logging.getLogger(__name__)


class DefaultPolicyService:
    def __init__(self, policy_service, tenant_service, default_policies):
        self._policy_service = policy_service
        self._tenant_service = tenant_service
        self._default_policies = default_policies

    def update_policies(self):
        top_tenant_uuid = self._tenant_service.find_top_tenant()
        logger.debug(
            'default_policies: found %s policies to apply',
            len(self._default_policies),
        )
        self.update_policies_for_tenant(top_tenant_uuid)
        commit_or_rollback()

    def update_policies_for_tenant(self, tenant_uuid):
        existing_policies = self._policy_service.list(scoping_tenant_uuid=tenant_uuid)
        existing_policy_slugs = {p['slug']: p['uuid'] for p in existing_policies}
        for slug, policy in self._default_policies.items():
            if slug in existing_policy_slugs:
                existing_policy_uuid = existing_policy_slugs[slug]
                self._update_policy(existing_policy_uuid, slug, policy)
            else:
                self._create_policy(tenant_uuid, slug, policy)

    def delete_orphan_policies(self):
        top_tenant_uuid = self._tenant_service.find_top_tenant()
        self.delete_orphan_policies_for_tenant(top_tenant_uuid)
        commit_or_rollback()

    def delete_orphan_policies_for_tenant(self, tenant_uuid):
        existing_policies = self._policy_service.list(scoping_tenant_uuid=tenant_uuid)
        for policy in existing_policies:
            if not policy['config_managed']:
                continue
            if policy['slug'] not in self._default_policies:
                self._delete_policy(tenant_uuid, policy['uuid'])

    def _create_policy(self, tenant_uuid, slug, policy):
        logger.debug('default_policies: creating policy %s', slug)
        policy.setdefault('description', 'Automatically created')
        self._policy_service.create(
            name=slug,
            slug=slug,
            tenant_uuid=tenant_uuid,
            config_managed=True,
            **policy,
        )

    def _update_policy(self, policy_uuid, policy_slug, policy):
        logger.debug('default_policies: updating policy %s', policy_uuid)
        policy.setdefault('description', 'Automatically created')
        self._policy_service.update(
            policy_uuid,
            name=policy_slug,
            config_managed=True,
            **policy,
        )

    def _delete_policy(self, tenant_uuid, policy_uuid):
        if self._policy_service.is_associated(policy_uuid):
            logger.warning(
                'default_policies: deleting policy %s (SKIPPED: associated)',
                policy_uuid,
            )
            return

        logger.debug('default_policies: deleting policy %s', policy_uuid)
        self._policy_service.delete(policy_uuid, tenant_uuid)
