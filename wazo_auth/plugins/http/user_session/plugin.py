# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from .http import UserSessions


class Plugin:

    def load(self, dependencies):
        api = dependencies['api']
        user_service = dependencies['user_service']

        api.add_resource(
            UserSessions,
            '/users/<uuid:user_uuid>/sessions',
            resource_class_args=(user_service,),
        )
