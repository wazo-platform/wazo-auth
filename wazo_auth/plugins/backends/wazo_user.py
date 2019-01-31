# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from wazo_auth import UserAuthenticationBackend

logger = logging.getLogger(__name__)


class WazoUser(UserAuthenticationBackend):

    def load(self, dependencies):
        super().load(dependencies)
        self._user_service = dependencies['user_service']
        self._group_service = dependencies['group_service']
        self._purposes = dependencies['purposes']

    def get_acls(self, login, args):
        backend_acl_templates = args.get('acl_templates', [])
        metadata = args.get('metadata', {})
        group_acl_templates = self._group_service.get_acl_templates(login)
        user_acl_templates = self._user_service.get_acl_templates(login)

        acl_templates = backend_acl_templates + group_acl_templates + user_acl_templates

        return self.render_acl(acl_templates, self.get_user_data, username=login, metadata=metadata)

    def verify_password(self, username, password, args):
        return self._user_service.verify_password(username, password)

    def get_metadata(self, login, args):
        metadata = {}
        purpose = self._user_service.list_users(username=login)[0]['purpose']
        for plugin in self._purposes.get(purpose).metadata_plugins:
            metadata.update(plugin.get_token_metadata(login, args))
        return metadata

    def get_user_data(self, *args, **kwargs):
        metadata = kwargs['metadata']
        result = {}
        purpose = self._user_service.get_user(metadata['uuid'])['purpose']
        for plugin in self._purposes.get(purpose).metadata_plugins:
            result.update(plugin.get_acl_metadata(uuid=metadata['uuid']))
        return result
