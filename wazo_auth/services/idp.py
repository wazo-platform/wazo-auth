# Copyright 2024-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from typing import Literal

from stevedore.extension import Extension

from wazo_auth.database.models import User
from wazo_auth.services.helpers import BaseService

IDPType = str | Literal['default']

# TODO: remove non-native authentication methods when they are migrated to idp plugins
HARDCODED_IDP_TYPES: set[IDPType] = {'native', 'default'}


class IDPService(BaseService):
    def __init__(self, dao, idp_plugins: dict[str, Extension]):
        super().__init__(dao)
        self._idp_plugins = idp_plugins

    def add_user(self, idp_type: IDPType, user_uuid: str) -> User:
        return self._dao.user.update(user_uuid, authentication_method=idp_type)

    def remove_user(self, idp_type: IDPType, user_uuid: str) -> User:
        user = self._dao.user.get(user_uuid)
        if user.authentication_method == idp_type:
            return self.add_user('default', user_uuid)
        return user

    def is_valid_idp_type(self, idp_type: IDPType) -> bool:
        return idp_type in self._idp_plugins or idp_type in HARDCODED_IDP_TYPES
