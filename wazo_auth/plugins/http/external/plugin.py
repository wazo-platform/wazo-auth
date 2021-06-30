# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['external_auth_service'],)

        api.add_resource(
            http.External,
            '/users/<uuid:user_uuid>/external',
            resource_class_args=args,
        )
        api.add_resource(
            http.ExternalConfig,
            '/external/<auth_type>/config',
            resource_class_args=args,
        )
