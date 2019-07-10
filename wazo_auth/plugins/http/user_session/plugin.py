# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:

    def load(self, dependencies):
        api = dependencies['api']
        user_service = dependencies['user_service']
        session_service = dependencies['session_service']

        api.add_resource(
            http.UserSessions,
            '/users/<uuid:user_uuid>/sessions',
            resource_class_args=(user_service,),
        )

        api.add_resource(
            http.UserSession,
            '/users/<uuid:user_uuid>/sessions/<uuid:session_uuid>',
            resource_class_args=(user_service, session_service),
        )
