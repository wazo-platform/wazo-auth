# Copyright 2018-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from wazo_auth import BaseMetadata

logger = logging.getLogger(__name__)


class DefaultUser(BaseMetadata):
    def load(self, dependencies):
        super().load(dependencies)
        self._user_service = dependencies['user_service']

    def get_token_metadata(self, login, args):
        user = self._user_service.list_users(username=login)[0]
        metadata = {
            'uuid': user['uuid'],
            'tenant_uuid': user['tenant_uuid'],
            'auth_id': user['uuid'],
            'pbx_user_uuid': user['uuid'],
            'xivo_uuid': self.get_xivo_uuid(args),
        }
        return metadata
