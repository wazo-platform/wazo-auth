# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['saml_config_service'],)

        api.add_resource(
            http.SAMLConfig,
            '/backends/saml',
            resource_class_args=args,
        )

        api.add_resource(
            http.SAMLMetadata,
            '/backends/saml/metadata',
            resource_class_args=args,
        )

        api.add_resource(
            http.SAMLSPMetadata,
            '/backends/saml/sp-metadata',
            resource_class_args=args,
        )

        api.add_resource(
            http.SAMLAcsUrlTemplate,
            '/backends/saml/acs_url_template',
            resource_class_args=args,
        )
