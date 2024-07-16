# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Any

from hamcrest import assert_that, calling, has_entries, not_, raises

from wazo_auth import exceptions

from .helpers import base, fixtures
from .helpers.constants import UNKNOWN_TENANT, UNKNOWN_UUID

TENANT_UUID_1 = '00000000-0000-4000-a000-000000000001'

DOMAINS = ['example.com']


@base.use_asset('database')
class TestSAMLConfigDAO(base.DAOTestCase):
    @fixtures.db.tenant(name='1', uuid=TENANT_UUID_1, domain_names=DOMAINS)
    @fixtures.db.saml_config(tenant_uuid=TENANT_UUID_1)
    def test_get(self, tenant_uuid, saml_config) -> None:
        config: dict[str, Any] = self._saml_config_dao.get(tenant_uuid)
        assert_that(
            config,
            has_entries(
                tenant_uuid=tenant_uuid,
                domain_uuid=saml_config['domain_uuid'],
                entity_id=saml_config['entity_id'],
                idp_metadata=saml_config['idp_metadata'],
                acs_url=saml_config['acs_url'],
            ),
        )

        assert_that(
            calling(self._saml_config_dao.get).with_args(UNKNOWN_UUID),
            raises(exceptions.UnknownSAMLConfigException),
        )

    @fixtures.db.tenant(name='1', uuid=TENANT_UUID_1, domain_names=DOMAINS)
    def test_create(self, tenant_uuid) -> None:
        domain = self._domain_dao.get(tenant_uuid)
        args = {
            'tenant_uuid': self.top_tenant_uuid,
            'acs_url': 'https://stack/api/0.1/saml/acs',
            'domain_uuid': domain[0].uuid,
            'entity_id': 'entity1',
            'idp_metadata': '<my_xml_data/>',
        }

        config_tenant: dict[str, Any] = self._saml_config_dao.create(**args)
        config: dict[str, Any] = self._saml_config_dao.get(config_tenant['tenant_uuid'])
        assert_that(config, has_entries(**args))

        assert_that(
            calling(self._saml_config_dao.create).with_args(**args),
            raises(exceptions.DuplicatedSAMLConfigException),
        )

    @fixtures.db.tenant(name='1', uuid=TENANT_UUID_1, domain_names=DOMAINS)
    @fixtures.db.saml_config(tenant_uuid=TENANT_UUID_1)
    def test_update(self, tenant_uuid, saml_config) -> None:
        args: dict[str, str] = {'acs_url': 'https://autre.url.com'}
        self._saml_config_dao.update(tenant_uuid, **args)
        config: dict[str, Any] = self._saml_config_dao.get(tenant_uuid)
        assert_that(config, has_entries(**args))

        assert_that(
            calling(self._saml_config_dao.update).with_args(UNKNOWN_TENANT),
            raises(exceptions.UnknownSAMLConfigException),
        )

    @fixtures.db.tenant(name='1', uuid=TENANT_UUID_1, domain_names=DOMAINS)
    @fixtures.db.saml_config(tenant_uuid=TENANT_UUID_1)
    def test_delete(self, tenant_uuid, saml_config) -> None:
        assert_that(
            calling(self._saml_config_dao.delete).with_args(UNKNOWN_TENANT),
            not_(raises(Exception)),
        )
        assert_that(
            calling(self._saml_config_dao.delete).with_args(tenant_uuid),
            not_(raises(Exception)),
        )
        assert_that(
            calling(self._saml_config_dao.get).with_args(tenant_uuid),
            raises(exceptions.UnknownSAMLConfigException),
        )

    @fixtures.db.tenant(name='1', uuid=TENANT_UUID_1, domain_names=DOMAINS)
    @fixtures.db.saml_config(tenant_uuid=TENANT_UUID_1)
    def test_exists(self, tenant_uuid, saml_config) -> None:
        assert_that(self._saml_config_dao.exists(tenant_uuid))
        assert_that(not_(self._saml_config_dao.exists(UNKNOWN_TENANT)))
