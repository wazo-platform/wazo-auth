# Copyright 2021-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from wazo_auth.database.helpers import commit_or_rollback

logger = logging.getLogger(__name__)


class DefaultPolicyService:
    def __init__(self, dao, default_policies):
        self._dao = dao
        self._default_policies = default_policies

    def update_policies(self, top_tenant_uuid):
        logger.debug(
            'default_policies: found %s policies to apply',
            len(self._default_policies),
        )
        self.update_policies_for_tenant(top_tenant_uuid)
        commit_or_rollback()

    def update_policies_for_tenant(self, tenant_uuid):
        for slug, policy_args in self._default_policies.items():
            policy = self._dao.policy.find_by(slug=slug, tenant_uuid=tenant_uuid)
            if policy:
                self._update_policy(policy.uuid, slug, policy_args)
            else:
                self._create_policy(tenant_uuid, slug, policy_args)

    def delete_orphan_policies(self):
        policies = self._dao.policy.list_(read_only=True)
        for policy in policies:
            if policy.slug not in self._default_policies:
                self._delete_policy(policy.uuid)
        commit_or_rollback()

    def _create_policy(self, tenant_uuid, slug, policy):
        logger.debug('default_policies: creating policy %s', slug)
        policy.setdefault('description', 'Automatically created')
        self._dao.policy.create(
            name=slug,
            slug=slug,
            tenant_uuid=tenant_uuid,
            config_managed=True,
            **policy,
        )

    def _update_policy(self, policy_uuid, policy_slug, policy):
        logger.debug('default_policies: updating policy %s', policy_uuid)
        policy.setdefault('description', 'Automatically created')
        self._dao.policy.update(
            policy_uuid,
            name=policy_slug,
            config_managed=True,
            **policy,
        )

    def _delete_policy(self, policy_uuid):
        if self._dao.policy.is_associated(policy_uuid):
            logger.warning(
                'default_policies: deleting policy %s (SKIPPED: associated)',
                policy_uuid,
            )
            return

        logger.debug('default_policies: deleting policy %s', policy_uuid)
        self._dao.policy.delete(policy_uuid, tenant_uuids=None)
