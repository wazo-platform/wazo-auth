# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from .http import SalesforceAuth

logger = logging.getLogger(__name__)

APP_CREDENTIAL_KEYS = ('client_id', 'client_secret')


class SalesforcePlugin:
    def load(self, dependencies):
        api = dependencies['api']
        config = dependencies['config']
        if any(key in config['salesforce'] for key in APP_CREDENTIAL_KEYS):
            logger.warning(
                'Ignoring salesforce.client_id and salesforce.client_secret in the '
                'config file: app credentials now live in '
                '/0.1/external/salesforce/config, per tenant'
            )
        args = (
            dependencies['external_auth_service'],
            dependencies['user_service'],
            config,
        )

        api.add_resource(
            SalesforceAuth,
            '/users/<uuid:user_uuid>/external/salesforce',
            resource_class_args=args,
        )
