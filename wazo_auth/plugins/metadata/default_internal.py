# Copyright 2018-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import BaseMetadata


class DefaultInternal(BaseMetadata):
    def get_token_metadata(self, login, args):
        metadata = super().get_token_metadata(login, args)
        metadata.update(purpose='internal')
        return metadata
