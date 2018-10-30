# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from wazo_auth import UserAuthenticationBackend

logger = logging.getLogger(__name__)


class WazoUser(UserAuthenticationBackend):

    def load(self, dependencies):
        super().load(dependencies)
        self._user_service = dependencies['user_service']
        self._group_service = dependencies['group_service']
        self._metadata_plugins = dependencies['metadata_plugins']

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
        metadata = {}
        for metadata_plugin in self._metadata_plugins:
            metadata.update(metadata_plugin.obj.get_token_metadata(login, args))
        return metadata

    def get_user_data(self, *args, **kwargs):
        metadata = kwargs['metadata']
        result = {}
        for metadata_plugin in self._metadata_plugins:
            result.update(metadata_plugin.obj.get_acl_metadata(uuid=metadata['uuid']))
        return result
