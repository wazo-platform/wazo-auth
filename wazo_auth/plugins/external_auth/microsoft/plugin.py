# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from .http import MicrosoftAuth

logger = logging.getLogger(__name__)


class MicrosoftPlugin:

    def load(self, dependencies):
        api = dependencies['api']
        config = dependencies['config']
        args = (dependencies['external_auth_service'], dependencies['user_service'], config)

        api.add_resource(
            MicrosoftAuth,
            '/users/<uuid:user_uuid>/external/microsoft',
            resource_class_args=args
        )
