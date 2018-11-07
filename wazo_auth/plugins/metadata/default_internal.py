# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from wazo_auth import BaseMetadata

logger = logging.getLogger(__name__)


class DefaultInternal(BaseMetadata):

    def load(self, dependencies):
        super().load(dependencies)
        self._tenant_service = dependencies['tenant_service']

    def get_token_metadata(self, login, args):
        metadata = super().get_token_metadata(login, args)
        metadata['uuid'] = metadata['auth_id']
        metadata['tenant_uuid'] = self._tenant_service.find_top_tenant()
        return metadata

    def get_acl_metadata(self, **kwargs):
        return {}
