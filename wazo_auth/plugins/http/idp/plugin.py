# Copyright 2024-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.services.idp import HARDCODED_IDP_TYPES

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']

        api.add_resource(
            http.IDPList,
            '/idp',
            resource_class_args=(
                {
                    idp_extension.obj.authentication_method
                    for idp_extension in dependencies['idp_plugins'].values()
                }
                | HARDCODED_IDP_TYPES,
            ),
        )
        api.add_resource(
            http.IDPUser,
            '/idp/<idp_type>/users/<uuid:user_uuid>',
            resource_class_args=(
                dependencies['user_service'],
                dependencies['idp_service'],
            ),
        )
        api.add_resource(
            http.IDPUsers,
            '/idp/<idp_type>/users',
            resource_class_args=(
                dependencies['user_service'],
                dependencies['idp_service'],
            ),
        )
