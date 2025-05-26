# Copyright 2024-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from uuid import uuid4

import requests
from hamcrest import assert_that, contains_inanyorder, has_entries

from .helpers import base, fixtures
from .helpers.base import assert_http_error, assert_no_error

TENANT_1_UUID = str(uuid4())
TENANT_2_UUID = str(uuid4())


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
        username='user1',
        tenant_uuid=TENANT_1_UUID,
        authentication_method='broken_verify_auth',
    )
    def test_broken_idp_login(self, tenant_1, user_1):
        # test a login attempt against an idp plugin implementation that fails
        # the login attempt
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

        # switch priority between two conflicting implementations
        idp_priority_config = {
            'idp_plugins': {
                'broken_verify_auth': {'priority': 4},
                'broken_verify_auth_replacement': {'priority': 3},
            }
        }
        with self.auth_with_config(idp_priority_config):
            assert_no_error(login_using_broken_verify_auth)

    @fixtures.http.tenant(uuid=TENANT_1_UUID)
    @fixtures.http.tenant(uuid=TENANT_2_UUID)
    @fixtures.http.user(
        tenant_uuid=TENANT_1_UUID, authentication_method='broken_verify_auth'
    )
    @fixtures.http.user(
        tenant_uuid=TENANT_2_UUID, authentication_method='broken_verify_auth'
    )
    def test_unavailable_idp_logs(self, tenant_1, tenant_2, user_1, user_2):
        # check logs
        expected_logs = [
            r'.*\(INFO\).*?Checking configured authentication methods '
            'for missing implementations'
        ]
        logs = self.asset_cls.service_logs('auth')
        unexpected_log = [
            r'.*\(WARNING\).*?Authentication method broken_verify_auth is in use '
            'but is not available'
        ]
        assert all(re.search(log, logs) for log in expected_logs)
        assert not any(re.search(log, logs) for log in unexpected_log)

        # disable broken_verify_auth plugin
        idp_priority_config = {
            'idp_plugins': {
                'broken_verify_auth': {'enabled': False},
                'broken_verify_auth_replacement': {'enabled': False},
            }
        }
        with self.asset_cls.capture_logs('auth') as result:
            with self.auth_with_config(idp_priority_config):
                pass

        logs = result.result()
        expected_logs += [
            r'.*\(WARNING\).*?Authentication method broken_verify_auth '
            'is in use but is not available',
            fr'.*\(WARNING\).*?User \(uuid={user_1["uuid"]}\) '
            r'has no available idp implementation '
            r'for authentication method broken_verify_auth',
            fr'.*\(WARNING\).*?User \(uuid={user_2["uuid"]}\) '
            r'has no available idp implementation '
            r'for authentication method broken_verify_auth',
        ]
        for log in expected_logs:
            assert re.search(log, logs)

    @fixtures.http.tenant(uuid=TENANT_1_UUID)
    @fixtures.http.user(
        tenant_uuid=TENANT_1_UUID,
        authentication_method='broken_verify_auth',
        username='user1',
    )
    def test_idp_with_refresh_token(self, tenant_1, user_1):
        idp_priority_config = {
            'idp_plugins': {
                'broken_verify_auth': {'priority': 4},
                'broken_verify_auth_replacement': {'priority': 3},
            }
        }
        client_id = 'my-test'
        with self.auth_with_config(idp_priority_config):
            response = requests.post(
                self.client.url('token'),
                json={
                    'broken_verify_auth': True,
                    'access_type': 'offline',
                    'client_id': client_id,
                },
                auth=(user_1['username'], user_1['password']),
            )
            response.raise_for_status()

            assert response.status_code == 200

            refresh_token = response.json()['data']['refresh_token']

            # login with refresh token
            response2 = requests.post(
                self.client.url('token'),
                json={
                    'refresh_token': refresh_token,
                    'client_id': client_id,
                    'expiration': 7200,
                },
            )
            response2.raise_for_status()
            assert response2.status_code == 200
