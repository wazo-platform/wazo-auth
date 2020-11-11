# Copyright 2017-2020 The Wazo Authors  (see the AUTHORS file)
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

    def get_acls(self, login, args):
        backend_acl_templates = args.get('acl_templates', [])
        group_acl_templates = self._group_service.get_acl_templates(login)
        user_acl_templates = self._user_service.get_acl_templates(login)

        acl_templates = backend_acl_templates + group_acl_templates + user_acl_templates

        return acl_templates

    def verify_password(self, username, password, args):
        return self._user_service.verify_password(username, password)

    def get_metadata(self, login, args):
        metadata = {}
        purpose = self._user_service.list_users(username=login)[0]['purpose']
        for plugin in self._purposes.get(purpose).metadata_plugins:
            metadata.update(plugin.get_token_metadata(login, args))
        return metadata
