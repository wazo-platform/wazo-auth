# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (
            dependencies['token_service'],
            dependencies['user_service'],
            dependencies['authentication_service'],
            dependencies['config'],
            dependencies['backends'],
        )

        api.add_resource(
            http.SAMLACS,
            '/saml/acs',
            resource_class_args=args,
        )
        api.add_resource(
            http.SAMLSSO,
            '/saml/sso',
            resource_class_args=args,
        )
