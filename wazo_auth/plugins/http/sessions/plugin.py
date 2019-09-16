# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:

    def load(self, dependencies):
        api = dependencies['api']
        session_service = dependencies['session_service']

        api.add_resource(
            http.Sessions,
            '/sessions',
            resource_class_args=[session_service],
        )
        api.add_resource(
            http.Session,
            '/sessions/<uuid:session_uuid>',
            resource_class_args=[session_service],
        )
