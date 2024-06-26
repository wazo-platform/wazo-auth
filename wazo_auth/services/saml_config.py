# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xml.etree import ElementTree

from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService


class SAMLConfigService(BaseService):
    def get(self, tenant_uuid: str) -> dict[str, str]:
        return self._dao.saml_config.get(tenant_uuid)

    def create_or_update(
        self, tenant_uuid: str, saml_config, etree_metadata: ElementTree.ElementTree
    ) -> dict[str, str]:
        metadata = ElementTree.tostring(etree_metadata.getroot()).decode()
        if self._dao.saml_config.exists(tenant_uuid):
            return self._dao.saml_config.update(
                tenant_uuid,
                saml_config['domain_uuid'],
                saml_config['entity_id'],
                metadata,
            )
        return self._dao.saml_config.create(
            tenant_uuid, saml_config['domain_uuid'], saml_config['entity_id'], metadata
        )

    def delete(self, tenant_uuid: str) -> None:
        if self._dao.saml_config.exists(tenant_uuid):
            return self._dao.saml_config.delete(tenant_uuid)
        raise exceptions.UnknownSAMLConfigException(tenant_uuid=tenant_uuid)

    def get_metadata(self, tenant_uuid: str) -> ElementTree.Element:
        etree_metadata: ElementTree.Element = ElementTree.fromstring(
            self._dao.saml_config.get(tenant_uuid)['idp_metadata']
        )
        return etree_metadata

    def get_acs_url(self, tenant_uuid: str) -> dict[str, str]:
        return {'acsUrl': 'http://localhost:9497/api/auth/v1/saml/acs'}
