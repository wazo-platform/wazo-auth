# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import (
    assert_that,
    equal_to,
    has_entries,
    has_key,
    not_,
)
from integration_tests.suite.helpers.constants import UNKNOWN_TENANT

from .helpers import base
from .helpers import fixtures


@base.use_asset('ldap')
class TestLDAPConfigAuth(base.APIIntegrationTest):
    @fixtures.http.ldap_config()
    def test_get_config(self, ldap_config):
        response = self.client.ldap_config.get(ldap_config['tenant_uuid'])
        assert_that(
            response, has_entries(tenant_uuid=ldap_config['tenant_uuid'])
        )

        base.assert_http_error(401, self.client.ldap_config.get, UNKNOWN_TENANT)

    def test_get_config_when_none(self):
        base.assert_http_error(404, self.client.ldap_config.get, self.top_tenant_uuid)

    def test_put_new_config(self):
        body = {
            'host': 'localhost',
            'port': 386,
            'protocol_version': 3,
            'protocol_security': None,
            'bind_dn': 'uid=admin,ou=people,dc=wazo-platform,dc=io',
            'bind_password': 'super-secret',
            'user_base_dn': 'ou=people,dc=wazo-platform,dc=io',
            'user_login_attribute': 'uid',
            'user_email_attribute': 'mail',
        }
        response = self.client.ldap_config.create_or_update(body)
        expected = {
            'host': 'localhost',
            'port': 386,
            'protocol_version': 3,
            'protocol_security': None,
            'bind_dn': 'uid=admin,ou=people,dc=wazo-platform,dc=io',
            'user_base_dn': 'ou=people,dc=wazo-platform,dc=io',
            'user_login_attribute': 'uid',
            'user_email_attribute': 'mail',
        }
        assert_that(response, has_entries(**expected))
        assert_that(response, not_(has_key('bind_password')))

    def test_put_new_config_errors(self):
        valid_body = {
            'host': 'localhost',
            'port': 386,
            'protocol_version': 3,
            'protocol_security': None,
            'bind_dn': 'uid=admin,ou=people,dc=wazo-platform,dc=io',
            'bind_password': 'super-secret',
            'user_base_dn': 'ou=people,dc=wazo-platform,dc=io',
            'user_login_attribute': 'uid',
            'user_email_attribute': 'mail',
        }
        invalid_bodies_modifications = [
            {'host': 1},
            {'host': True},
            {'host': 'a' * 513},
            {'host': []},
            {'host': {}},
            {'host': None},
            {'port': True},
            {'port': 'a' * 513},
            {'port': []},
            {'port': {}},
            {'port': None},
            {'protocol_version': 'patate'},
            {'protocol_version': True},
            {'protocol_version': []},
            {'protocol_version': {}},
            {'protocol_security': 'patate'},
            {'protocol_security': True},
            {'protocol_security': []},
            {'protocol_security': {}},
            {'bind_dn': 1},
            {'bind_dn': True},
            {'bind_dn': 'a' * 257},
            {'bind_dn': []},
            {'bind_dn': {}},
            {'bind_password': 1},
            {'bind_password': True},
            {'bind_password': []},
            {'bind_password': {}},
            {'user_base_dn': 1},
            {'user_base_dn': 'a' * 257},
            {'user_base_dn': True},
            {'user_base_dn': []},
            {'user_base_dn': {}},
            {'user_login_attribute': 1},
            {'user_login_attribute': True},
            {'user_login_attribute': 'a' * 65},
            {'user_login_attribute': []},
            {'user_login_attribute': {}},
            {'user_email_attribute': 1},
            {'user_email_attribute': True},
            {'user_email_attribute': 'a' * 65},
            {'user_email_attribute': []},
            {'user_email_attribute': {}},
        ]

        for invalid_modification in invalid_bodies_modifications:
            body_copy = valid_body.copy()
            body_copy.update(invalid_modification)
            base.assert_http_error(400, self.client.ldap_config.create_or_update, body_copy)

    @fixtures.http.ldap_config()
    def test_put_config_when_already_exists(self, ldap_config):
        new_body = {
            'host': 'patate',
            'port': 689,
            'protocol_version': 2,
            'protocol_security': 'ldaps',
            'bind_dn': 'uid=root,ou=people,dc=wazo-platform,dc=io',
            'bind_password': 'not-so-super-secret',
            'user_base_dn': 'ou=genses,dc=wazo-platform,dc=io',
            'user_login_attribute': 'cn',
            'user_email_attribute': 'email',
        }
        result = self.client.ldap_config.create_or_update(new_body)
        expected = {
            'host': 'patate',
            'port': 689,
            'protocol_version': 2,
            'protocol_security': 'ldaps',
            'bind_dn': 'uid=root,ou=people,dc=wazo-platform,dc=io',
            'user_base_dn': 'ou=genses,dc=wazo-platform,dc=io',
            'user_login_attribute': 'cn',
            'user_email_attribute': 'email',
        }
        assert_that(result, has_entries(**expected))
        assert_that(result, not_(has_key('bind_password')))

    @fixtures.http.ldap_config()
    def test_put_multi_tenant(self, ldap_config):
        with self.client_in_subtenant() as (client, _, tenant):
            result = client.ldap_config.create_or_update(ldap_config)
            assert_that(result, has_entries(tenant_uuid=tenant['uuid']))

    def test_delete_config(self):
        pass

    def test_delete_config_when_none_exists(self):
        pass
