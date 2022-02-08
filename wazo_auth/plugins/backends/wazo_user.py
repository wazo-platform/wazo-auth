# Copyright 2017-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from wazo_auth import BaseAuthenticationBackend

logger = logging.getLogger(__name__)


class WazoUser(BaseAuthenticationBackend):
    def load(self, dependencies):
        super().load(dependencies)
        self._user_service = dependencies['user_service']
        self._group_service = dependencies['group_service']
        self._purposes = dependencies['purposes']

    def get_acl(self, login, args):
        backend_acl = args.get('acl', [])
        user_uuid = self._user_service.get_user_uuid_by_login(login)
        group_acl = self._group_service.get_acl(user_uuid)
        user_acl = self._user_service.get_acl(user_uuid)
        return backend_acl + group_acl + user_acl

    def verify_password(self, login, password, args):
        return self._user_service.verify_password(login, password)

    def get_metadata(self, login, args):
        metadata = {}
        user_uuid = self._user_service.get_user_uuid_by_login(login)
        purpose = self._user_service.list_users(uuid=user_uuid)[0]['purpose']
        for plugin in self._purposes.get(purpose).metadata_plugins:
            metadata.update(plugin.get_token_metadata(login, args))
        return metadata
