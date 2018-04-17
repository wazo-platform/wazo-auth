# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from wazo_auth import UserAuthenticationBackend

logger = logging.getLogger(__name__)


class WazoUser(UserAuthenticationBackend):

    def load(self, dependencies):
        super(WazoUser, self).load(dependencies)
        self._user_service = dependencies['user_service']
        self._group_service = dependencies['group_service']

    def get_acls(self, username, args):
        backend_acl_templates = args.get('acl_templates', [])
        metadata = args.get('metadata', {})
        group_acl_templates = self._group_service.get_acl_templates(username)
        user_acl_templates = self._user_service.get_acl_templates(username)

        acl_templates = backend_acl_templates + group_acl_templates + user_acl_templates

        return self.render_acl(acl_templates, self.get_user_data, username=username, metadata=metadata)

    def verify_password(self, username, password, args):
        return self._user_service.verify_password(username, password)

    def get_metadata(self, login, args):
        metadata = super(WazoUser, self).get_metadata(login, args)
        user_uuid = self._get_user_uuid(login)
        groups = self._get_groups(user_uuid)
        user = self._user_service.get_user(user_uuid)

        user_data = {
            'auth_id': user_uuid,
            'xivo_user_uuid': user_uuid,
            'uuid': user_uuid,
            'tenant_uuid': user['tenant_uuid'],
            'groups': groups,
        }
        metadata.update(user_data)

        return metadata

    def get_user_data(self, *args, **kwargs):
        metadata = kwargs['metadata']

        result = super(WazoUser, self).get_user_data(uuid=metadata['uuid'])
        result.update(metadata)

        return result

    def _get_tenants(self, user_uuid):
        result = []
        tenants = self._user_service.list_tenants(user_uuid)

        for tenant in tenants:
            result.append(
                {
                    'uuid': tenant['uuid'],
                    'name': tenant['name'],
                }
            )

        return result

    def _get_groups(self, user_uuid):
        result = []
        groups = self._user_service.list_groups(user_uuid)

        for group in groups:
            group_members = self._group_service.list_users(group['uuid'])
            member_uuids = [{'uuid': u['uuid']} for u in group_members]
            result.append(
                {
                    'uuid': group['uuid'],
                    'name': group['name'],
                    'users': member_uuids,
                }
            )

        return result

    def _get_user_uuid(self, username):
        matching_users = self._user_service.list_users(username=username)
        return matching_users[0]['uuid']
