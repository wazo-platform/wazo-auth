# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']

        api.add_resource(
            http.SAMLACS,
            '/saml/acs',
            resource_class_args=(dependencies['saml_service'],),
        )
        api.add_resource(
            http.SAMLSSO,
            '/saml/sso',
            resource_class_args=(dependencies['saml_service'],),
        )
        api.add_resource(
            http.SAMLLogout,
            '/saml/logout',
            resource_class_args=(
                dependencies['saml_service'],
                dependencies['token_service'],
            ),
        )
        api.add_resource(
            http.SAMLSLS,
            '/saml/sls',
            resource_class_args=(dependencies['saml_service'],),
        )
