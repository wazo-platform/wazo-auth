# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from wazo_auth import BaseMetadata


class DefaultExternalAPI(BaseMetadata):

    def load(self, dependencies):
        super().load(dependencies)

    def get_token_metadata(self, login, args):
        metadata = super().get_token_metadata(login, args)
        metadata['uuid'] = metadata['auth_id']
        return metadata

    def get_acl_metadata(self, **kwargs):
        return {}
