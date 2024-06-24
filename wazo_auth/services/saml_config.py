# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.services.helpers import BaseService


class SAMLConfigService(BaseService):
    def get(self, tenant_uuid: str) -> dict[str, str]:
        return {'entityId': 'id'}

    def create_or_update(
        self, tenant_uuid: str, saml_config, metadata_file
    ) -> dict[str, str]:
        return {'entityId': 'id'}

    def delete(self, tenant_uuid: str) -> str:
        return "entityId"

    def get_metadata_path(self, tenant_uuid: str) -> str:
        return '/tmp/xml.xml'

    def get_acs_url(self, tenant_uuid: str) -> dict[str, str]:
        return {'acsUrl': 'http://localhost:9497/api/auth/v1/saml/acs'}
