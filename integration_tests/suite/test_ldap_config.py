# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import (
    assert_that,
    has_entries,
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
