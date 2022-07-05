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
        for slug, group_args in self._default_groups.items():
            group = self._dao.group.find_by(name=slug, tenant_uuid=tenant_uuid)
            if group:
                self._update_group(tenant_uuid, group.uuid, slug, group_args)
            else:
                self._create_group(tenant_uuid, slug, group_args)

    def _create_group(self, tenant_uuid, group_slug, group):
        logger.debug('Tenant %s: creating group %s', tenant_uuid, group_slug)
        self._dao.group.create(
            name=group_slug,
            tenant_uuid=tenant_uuid,
            system_managed=False,
            **group,
        )

    def _update_group(self, tenant_uuid, group_uuid, group_slug, group):
        logger.debug('Tenant %s: updating group %s', tenant_uuid, group_slug)
        self._dao.group.update(
            group_uuid,
            name=group_slug,
            **group,
        )
