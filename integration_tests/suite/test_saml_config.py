# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import assert_that, has_entries, is_

from wazo_auth.config import _DEFAULT_CONFIG

from .helpers import base, fixtures
from .helpers.base import assert_http_error
from .helpers.constants import UNKNOWN_TENANT

DOMAINS = ['example.com']


@base.use_asset('base')
class TestSAMLConfig(base.APIIntegrationTest):
    def test_create(self):
        tenant = self.client.tenants.new(domain_names=DOMAINS)
        try:
            config = {
                'data': {
                    'acs_url': 'https://stack.wazo.local/api/0.1/saml/acs',
                    'entity_id': 'wazo.dev',
                    'domain_uuid': self.client.tenants.get_domains(tenant['uuid'])[
                        'items'
                    ][0]['uuid'],
                },
                'files': {'metadata': fixtures.http.SAML_METADATA},
            }
            saml_config = self.client.saml_config.create(tenant['uuid'], **config)
            assert_that(saml_config, has_entries(**config['data']))

            result = self.client.saml_config.get(tenant['uuid'])
            assert_that(result, has_entries(**config['data']))
        finally:
            self.client.saml_config.delete(tenant['uuid'])
            self.client.tenants.delete(tenant['uuid'])

    def test_create_domain_outside_tenant(self):
        tenant1 = self.client.tenants.new(domain_names=DOMAINS)
        tenant2 = self.client.tenants.new(domain_names=['autre.com'])
        try:
            config = {
                'data': {
                    'acs_url': 'https://stack.wazo.local/api/0.1/saml/acs',
                    'entity_id': 'wazo.dev',
                    'domain_uuid': self.client.tenants.get_domains(tenant2['uuid'])[
                        'items'
                    ][0]['uuid'],
                },
                'files': {'metadata': fixtures.http.SAML_METADATA},
            }
            base.assert_http_error(
                400, self.client.saml_config.create, tenant1['uuid'], **config
            )

        finally:
            self.client.tenants.delete(tenant1['uuid'])
            self.client.tenants.delete(tenant2['uuid'])

    @fixtures.http.saml_config(DOMAINS)
    def test_get_config(self, config):
        response = self.client.saml_config.get(config['tenant_uuid'])
        assert_that(response, has_entries(**config))

        base.assert_http_error(401, self.client.saml_config.get, UNKNOWN_TENANT)

    @fixtures.http.saml_config(DOMAINS)
    def test_update_config(self, config):
        change = {'data': {'entity_id': 'new_entity_id'}}
        self.client.saml_config.update(config['tenant_uuid'], **change)
        updated = self.client.saml_config.get(config['tenant_uuid'])
        config['entity_id'] = 'new_entity_id'
        assert_that(updated, has_entries(**config))

    @fixtures.http.saml_config(DOMAINS)
    def test_update_config_domain_outside_tenant(self, config):
        tenant2 = self.client.tenants.new(domain_names=['autre.com'])
        outside_domain_uuid = (
            self.client.tenants.get_domains(tenant2['uuid'])['items'][0]['uuid'],
        )
        try:
            change = {'data': {'domain_uuid': outside_domain_uuid}}
            base.assert_http_error(
                400, self.client.saml_config.update, config['tenant_uuid'], **change
            )
        finally:
            self.client.tenants.delete(tenant2['uuid'])

    @fixtures.http.saml_config(DOMAINS)
    def test_delete_config(self, config):
        response = self.client.saml_config.get(config['tenant_uuid'])
        assert_that(response, has_entries(**config))
        self.client.saml_config.delete(config['tenant_uuid'])
        assert_http_error(404, self.client.saml_config.get, config['tenant_uuid'])

    @fixtures.http.saml_config(DOMAINS)
    def test_get_metadata(self, config):
        response = self.client.saml_config.get_metadata(config['tenant_uuid'])
        assert_that(response.decode(), is_(fixtures.http.SAML_METADATA))

    def test_acs_template(self):
        response = self.client.saml_config.get_acs_template()
        assert_that(
            response, is_({'acs_url': _DEFAULT_CONFIG['saml']['acs_url_template']})
        )
