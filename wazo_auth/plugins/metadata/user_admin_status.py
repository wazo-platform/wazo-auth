# Copyright 2022-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from wazo_auth import BaseMetadata

logger = logging.getLogger(__name__)


class UserAdminStatus(BaseMetadata):
    def get_token_metadata(self, login, args):
        metadata = super().get_token_metadata(login, args)
        return {'admin': self._is_admin(metadata['auth_id'])}

    def _is_admin(self, user_uuid):
        result = self._user_service.list_policies(
            user_uuid=user_uuid, slug='wazo_default_admin_policy'
        )
        return bool(result)
