# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from .http import SalesforceAuth
from .token import EXPIRATION_MARGIN

logger = logging.getLogger(__name__)

APP_CREDENTIAL_KEYS = ('client_id', 'client_secret')
DEFAULT_ACCESS_TOKEN_LIFETIME = 7200


class SalesforcePlugin:
    def load(self, dependencies):
        api = dependencies['api']
        section = dict(dependencies['config']['salesforce'])
        if any(key in section for key in APP_CREDENTIAL_KEYS):
            logger.warning(
                'Ignoring salesforce.client_id and salesforce.client_secret in the '
                'config file: app credentials now live in '
                '/0.1/external/salesforce/config, per tenant'
            )
        for key in APP_CREDENTIAL_KEYS:
            section.pop(key, None)
        section['access_token_lifetime'] = _access_token_lifetime(
            section.get('access_token_lifetime')
        )
        args = (
            dependencies['external_auth_service'],
            dependencies['user_service'],
            section,
        )

        api.add_resource(
            SalesforceAuth,
            '/users/<uuid:user_uuid>/external/salesforce',
            resource_class_args=args,
        )


def _access_token_lifetime(value):
    try:
        lifetime = int(value)
    except (TypeError, ValueError):
        lifetime = None
    if lifetime is None or lifetime <= EXPIRATION_MARGIN:
        logger.warning(
            'salesforce.access_token_lifetime %r is not a number of seconds above '
            '%s: using %s',
            value,
            EXPIRATION_MARGIN,
            DEFAULT_ACCESS_TOKEN_LIFETIME,
        )
        return DEFAULT_ACCESS_TOKEN_LIFETIME
    return lifetime
