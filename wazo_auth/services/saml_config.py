# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
from xml.etree import ElementTree

from wazo_auth.database.models import Domain, SAMLConfig
from wazo_auth.plugins.http.saml_config.schemas import saml_config_schema
from wazo_auth.services.helpers import BaseService

logger = logging.getLogger(__name__)


class SAMLConfigService(BaseService):
    def __init__(self, config, saml_service, dao) -> None:
        self._xml_files_dir: str = config['saml']['xml_files_dir']
        self._saml_service = saml_service
        super().__init__(dao)
        self._reload_saml_service()

    def _get_metadata_path(self, tenant_uuid: str) -> str:
        return self._xml_files_dir + '/' + tenant_uuid + '.xml'

    def _update_xml_metadata(
        self, tenant_uuid: str, etree_metadata: ElementTree.ElementTree
    ) -> None:
        etree_metadata.write(self._get_metadata_path(tenant_uuid))

    def _delete_conf(self, tenant_uuid: str) -> None:
        os.remove(self._xml_files_dir + '/' + tenant_uuid + '.xml')

    def get(self, tenant_uuid: str) -> dict[str, str]:
        return self._dao.saml_config.get(tenant_uuid)

    def create_or_update(
        self, tenant_uuid: str, saml_config, etree_metadata: ElementTree.ElementTree
    ) -> None:
        metadata = ElementTree.tostring(etree_metadata.getroot()).decode()
        kwargs = {
            'tenant_uuid': tenant_uuid,
            'domain_uuid': saml_config['domain_uuid'],
            'entity_id': saml_config['entity_id'],
            'idp_metadata': metadata,
        }
        if self._dao.saml_config.exists(tenant_uuid):
            self._dao.saml_config.update(**kwargs)
        else:
            self._dao.saml_config.create(**kwargs)
        self._update_xml_metadata(tenant_uuid, etree_metadata)
        self._reload_saml_service()

    def delete(self, tenant_uuid: str) -> None:
        self._dao.saml_config.delete(tenant_uuid)
        self._delete_conf(tenant_uuid)
        self._reload_saml_service()

    def get_metadata(self, tenant_uuid: str) -> ElementTree.Element:
        etree_metadata: ElementTree.Element = ElementTree.fromstring(
            self._dao.saml_config.get(tenant_uuid)['idp_metadata']
        )
        return etree_metadata

    def get_acs_url(self, tenant_uuid: str) -> dict[str, str]:
        return {'acsUrl': 'http://localhost:9497/api/auth/v1/saml/acs'}

    def _update_domain_name(self, item, domains) -> dict[str, str]:
        domain_name: list[str] = [
            domain.name for domain in domains if domain.uuid == item['domain_uuid']
        ]
        if domain_name[0]:
            item['domain_name'] = domain_name[0]
            return item
        assert f'Database consistency error, domain name for {item}/{domains}'
        return {}

    def _add_metadata_path(self, item) -> dict[str, str]:
        item['metadata_path'] = self._get_metadata_path(item['tenant_uuid'])
        return item

    def _update_item(self, item, domains) -> dict[str, str]:
        item = self._update_domain_name(item, domains)
        item = self._add_metadata_path(item)
        return item

    def _reload_saml_service(self) -> None:
        db_configs: list[SAMLConfig] = self._dao.saml_config.list()
        domains: list[Domain] = self._dao.domain.list()
        saml_configs = [saml_config_schema.dump(item) for item in db_configs]
        configs_domain_names: list[dict[str, str]] = [
            self._update_item(item, domains) for item in saml_configs
        ]
        self._saml_service.init_clients(configs_domain_names)
        return None
