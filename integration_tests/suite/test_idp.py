# Copyright 2024-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from uuid import uuid4

import requests
from hamcrest import assert_that, contains_inanyorder, has_entries

from .helpers import base, fixtures
from .helpers.base import assert_http_error

TENANT_1_UUID = str(uuid4())


@base.use_asset('base')
class TestAuthenticationMethods(base.APIIntegrationTest):
    def test_authentication_backend_list(self):
        response = self.client.idp.list()

        assert_that(
            response,
            has_entries(
                total=6,
                filtered=6,
                items=contains_inanyorder(
                    'ldap',
                    'native',
                    'saml',
                    'default',
                    'broken_can_authenticate',
                    'broken_verify_auth',
                ),
            ),
        )

    @fixtures.http.tenant(uuid=TENANT_1_UUID)
    @fixtures.http.user(
        tenant_uuid=TENANT_1_UUID, authentication_method='broken_verify_auth'
    )
    def test_broken_idp_login(self, tenant_1, user_1):
        # test a login attempt against an idp plugin implementation that fails the login attempt
        def login_using_broken_verify_auth():
            response = requests.post(
                self.client.url('token'),
                json={
                    'broken_verify_auth': True,
                    'expiration': 7200,
                },
                auth=(user_1['username'], user_1['password']),
            )
            response.raise_for_status()

        assert_http_error(401, login_using_broken_verify_auth)
