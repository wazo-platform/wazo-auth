# Copyright 2024-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from uuid import uuid4

from wazo_auth_client import Client as AuthClient

from wazo_auth import BaseMetadata, helpers

logger = logging.getLogger(__name__)


class Plugin(BaseMetadata):
    def load(self, dependencies):
        logger.debug('loading metadata plugin')
        super().load(dependencies)
        self._token_service = dependencies['token_service']
        self.token_renewer = helpers.LocalTokenRenewer(
            self._token_service, acl=['test.internal_token']
        )

    def get_token_metadata(self, login, args):
        metadata = super().get_token_metadata(login, args)

        token = self.token_renewer.get_token()
        client = AuthClient(host='auth', port=9497, https=False, prefix=None)
        is_valid = client.token.is_valid(
            token, tenant=self._token_service.top_tenant_uuid
        )

        metadata['internal_token_is_valid'] = is_valid
        return metadata

    def get_persistent_metadata(self, login, args):
        logger.debug('computing persistent metadata for %s: %s', login, args)
        metadata = super().get_persistent_metadata(login, args)

        metadata.update(
            persistent=str(uuid4()),
        )
        return metadata
