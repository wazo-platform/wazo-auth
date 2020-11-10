# Copyright 2018-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from wazo_auth import BaseMetadata

logger = logging.getLogger(__name__)


class DefaultUser(BaseMetadata):
    def load(self, dependencies):
        super().load(dependencies)
        self._user_service = dependencies['user_service']
        self._group_service = dependencies['group_service']
        self._tenant_service = dependencies['tenant_service']
        self._config = dependencies['config']

    def get_token_metadata(self, login, args):
        user_uuid = self._get_user_uuid(login)
        groups = self._get_groups(user_uuid)
        user = self._user_service.get_user(user_uuid)
        tenant_uuid = user['tenant_uuid']
        tenant = self._tenant_service.get(
            scoping_tenant_uuid=tenant_uuid, uuid=tenant_uuid
        )
        sub_tenants = self._tenant_service.list_(tenant_uuid)

        metadata = {
            'auth_id': user_uuid,
            'username': login,
            'pbx_user_uuid': user_uuid,
            'xivo_user_uuid': user_uuid,  # For API compatibility
            'user_uuid': user_uuid,
            'xivo_uuid': self.get_xivo_uuid(args),
            'uuid': user_uuid,
            'tenant_uuid': user['tenant_uuid'],
            'visible_tenants': (
                [{'uuid': tenant['uuid'], 'name': tenant['name']}]
                + [
                    {'uuid': sub_tenant['uuid'], 'name': sub_tenant['name']}
                    for sub_tenant in sub_tenants
                ]
            ),
            'groups': groups,
        }
        return metadata

    def get_acl_metadata(self, **kwargs):
        return {}

    def _get_user_uuid(self, username):
        matching_users = self._user_service.list_users(username=username)
        return matching_users[0]['uuid']

    def _get_groups(self, user_uuid):
        result = []
        groups = self._user_service.list_groups(user_uuid)

        for group in groups:
            group_members = self._group_service.list_users(group['uuid'])
            member_uuids = [{'uuid': u['uuid']} for u in group_members]
            result.append(
                {'uuid': group['uuid'], 'name': group['name'], 'users': member_uuids}
            )

        return result
