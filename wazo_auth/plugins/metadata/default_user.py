# Copyright 2018-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from wazo_auth import BaseMetadata

logger = logging.getLogger(__name__)


class DefaultUser(BaseMetadata):
    def get_token_metadata(self, login, args):
        default_metadata = super().get_token_metadata(login, args)
        metadata = {
            'uuid': default_metadata['uuid'],
            'tenant_uuid': default_metadata['tenant_uuid'],
            'auth_id': default_metadata['auth_id'],
            'pbx_user_uuid': default_metadata['uuid'],
            'xivo_uuid': default_metadata['xivo_uuid'],
        }
        return metadata
