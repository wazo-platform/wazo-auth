# Copyright 2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from .http import GeminiAuth

class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (
            dependencies['external_auth_service'],
        )

        api.add_resource(
            GeminiAuth,
            '/users/<uuid:user_uuid>/external/gemini',
            resource_class_args=args,
        )

