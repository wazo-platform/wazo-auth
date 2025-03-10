# Copyright 2024-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import uuid

from hamcrest import assert_that, has_entries

from .helpers import base, fixtures
from .helpers.base import assert_http_error, assert_no_error
from .helpers.constants import UNKNOWN_UUID

TENANT_UUID_1 = str(uuid.uuid4())
TENANT_UUID_2 = str(uuid.uuid4())


@base.use_asset('base')
class TestIDPUserAssociation(base.APIIntegrationTest):
    @fixtures.http.tenant(uuid=TENANT_UUID_1)
    @fixtures.http.tenant(uuid=TENANT_UUID_2)
    @fixtures.http.user(tenant_uuid=TENANT_UUID_1, authentication_method='default')
    @fixtures.http.user(tenant_uuid=TENANT_UUID_2, authentication_method='default')
    def test_put(self, tenant_1, tenant_2, user_1, user_2):
        assert_http_error(404, self.client.idp.add_user, 'unknown', user_1['uuid'])
        assert_http_error(404, self.client.idp.add_user, 'native', UNKNOWN_UUID)

        assert_no_error(self.client.idp.add_user, 'native', user_1['uuid'])
        user = self.client.users.get(user_1['uuid'])
        assert_that(user, has_entries(authentication_method='native'))
        assert_no_error(self.client.idp.add_user, 'native', user_1['uuid'])  # Twice

        with self.client_in_subtenant() as (client, user_3, _):
            # User is not visible to this sub tenant
            assert_http_error(404, client.idp.add_user, 'native', user_2['uuid'])

            # Master tenant can manage sub tenant
            assert_no_error(self.client.idp.add_user, 'native', user_3['uuid'])
            user = self.client.users.get(user_3['uuid'])
            assert_that(user, has_entries(authentication_method='native'))

        valid_idp_types = [
            'saml',
            'native',
            'default',
            'ldap',
            'broken_can_authenticate',
            'broken_verify_auth',
        ]
        for t in valid_idp_types:
            assert_no_error(self.client.idp.add_user, t, user_1['uuid'])
            user = self.client.users.get(user_1['uuid'])
            assert_that(user, has_entries(authentication_method=t))

    @fixtures.http.tenant(uuid=TENANT_UUID_1)
    @fixtures.http.tenant(uuid=TENANT_UUID_2)
    @fixtures.http.user(tenant_uuid=TENANT_UUID_1, authentication_method='saml')
    @fixtures.http.user(tenant_uuid=TENANT_UUID_2, authentication_method='native')
    def test_delete(self, tenant_1, tenant_2, user_1, user_2):
        assert_http_error(404, self.client.idp.remove_user, 'unknown', user_1['uuid'])
        assert_http_error(404, self.client.idp.remove_user, 'native', UNKNOWN_UUID)

        # Not native, nothing to change
        assert_no_error(self.client.idp.remove_user, 'native', user_1['uuid'])
        user = self.client.users.get(user_1['uuid'])
        assert_that(user, has_entries(authentication_method='saml'))

        with self.client_in_subtenant() as (client, user_3, _):
            # User is not visible to this sub tenant
            assert_http_error(404, client.idp.remove_user, 'native', user_2['uuid'])

            # Master tenant can manage sub tenant
            client.idp.add_user('native', user_3['uuid'])
            assert_no_error(self.client.idp.remove_user, 'native', user_3['uuid'])
            user = self.client.users.get(user_3['uuid'])
            assert_that(user, has_entries(authentication_method='default'))

        valid_idp_types = [
            'saml',
            'native',
            'ldap',
            'broken_can_authenticate',
            'broken_verify_auth',
        ]
        for t in valid_idp_types:
            self.client.idp.add_user(t, user_1['uuid'])
            assert_no_error(self.client.idp.remove_user, t, user_1['uuid'])
            user = self.client.users.get(user_1['uuid'])
            assert_that(user, has_entries(authentication_method='default'))

    @fixtures.http.tenant(uuid=TENANT_UUID_1)
    @fixtures.http.tenant(uuid=TENANT_UUID_2)
    @fixtures.http.user(tenant_uuid=TENANT_UUID_1, authentication_method='default')
    @fixtures.http.user(tenant_uuid=TENANT_UUID_1, authentication_method='default')
    @fixtures.http.user(tenant_uuid=TENANT_UUID_2, authentication_method='default')
    def test_put_multiple_users(self, tenant_1, tenant_2, user_1, user_2, user_3):
        assert_http_error(400, self.client.idp.add_users, 'native', user_1)
        assert_http_error(400, self.client.idp.add_users, 'native', [user_1['uuid']])

        assert_http_error(404, self.client.idp.add_users, 'unknown', [user_1])
        assert_http_error(
            404, self.client.idp.add_users, 'native', [{'uuid': UNKNOWN_UUID}]
        )

        assert_no_error(self.client.idp.add_users, 'native', [user_1, user_2])
        user = self.client.users.get(user_1['uuid'])
        assert_that(user, has_entries(authentication_method='native'))
        user = self.client.users.get(user_2['uuid'])
        assert_that(user, has_entries(authentication_method='native'))

        with self.client_in_subtenant() as (client, user_4, _):
            # user_2 is not visible to this sub tenant
            assert_http_error(404, client.idp.add_users, 'native', [user_3, user_4])

            # Master tenant can manage sub tenant
            assert_no_error(self.client.idp.add_users, 'native', [user_3, user_4])
            user = self.client.users.get(user_3['uuid'])
            assert_that(user, has_entries(authentication_method='native'))
            user = self.client.users.get(user_4['uuid'])
            assert_that(user, has_entries(authentication_method='native'))

        valid_idp_types = [
            'saml',
            'native',
            'default',
            'ldap',
            'broken_can_authenticate',
            'broken_verify_auth',
        ]
        for t in valid_idp_types:
            assert_no_error(self.client.idp.add_users, t, [user_1])
            user = self.client.users.get(user_1['uuid'])
            assert_that(user, has_entries(authentication_method=t))
