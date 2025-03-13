# Copyright 2017-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['user_service'], dependencies['idp_service'])

        api.add_resource(
            http.Users,
            '/users',
            resource_class_args=args,
        )
        api.add_resource(
            http.User,
            '/users/<uuid:user_uuid>',
            resource_class_args=args,
        )
        api.add_resource(
            http.UserPassword,
            '/users/<uuid:user_uuid>/password',
            resource_class_args=args,
        )
