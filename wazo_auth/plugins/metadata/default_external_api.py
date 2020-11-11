# Copyright 2018-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import BaseMetadata


class DefaultExternalAPI(BaseMetadata):
    def load(self, dependencies):
        super().load(dependencies)
        self._user_service = dependencies['user_service']

    def get_token_metadata(self, login, args):
        metadata = super().get_token_metadata(login, args)
        user_uuid = self._get_user_uuid(login)
        user = self._user_service.get_user(user_uuid)

        metadata['uuid'] = metadata['auth_id']
        metadata['tenant_uuid'] = user['tenant_uuid']
        return metadata

    def _get_user_uuid(self, username):
        matching_users = self._user_service.list_users(username=username)
        return matching_users[0]['uuid']
