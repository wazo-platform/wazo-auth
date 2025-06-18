# Copyright 2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.interfaces import BaseMetadata
from wazo_auth.purpose import Purposes
from wazo_auth.services import UserService


class MetadataByPurposeMixin:
    _purposes: Purposes
    _user_service: UserService

    def get_metadata_plugins_by_purpose(self, purpose: str) -> list[BaseMetadata]:
        return self._purposes.get(purpose).metadata_plugins

    def get_metadata_plugins_by_login(self, login: str) -> list[BaseMetadata]:
        user_uuid = self._user_service.get_user_uuid_by_login(login)
        return self.get_metadata_plugins_by_uuid(user_uuid)

    def get_metadata_plugins_by_uuid(self, uuid: str) -> list[BaseMetadata]:
        user = self._user_service.list_users(uuid=uuid)[0]
        purpose = user['purpose']
        return self.get_metadata_plugins_by_purpose(purpose)
