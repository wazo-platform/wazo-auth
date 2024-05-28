# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']

        api.add_resource(
            http.IDPList,
            '/idp',
        )

        api.add_resource(
            http.IDPUser,
            '/idp/<idp_type>/users/<uuid:user_uuid>',
            resource_class_args=(
                dependencies['user_service'],
                dependencies['idp_service'],
            ),
        )
