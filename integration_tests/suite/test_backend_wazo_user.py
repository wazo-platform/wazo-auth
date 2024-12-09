# Copyright 2017-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from uuid import uuid4

from hamcrest import assert_that, has_entries, has_item
from wazo_test_helpers.hamcrest.uuid_ import uuid_

from .helpers import base, fixtures
from .helpers.base import assert_http_error

NEW_TENANT_UUID = str(uuid4())


@base.use_asset('base')
class TestWazoUserBackend(base.APIIntegrationTest):
    @fixtures.http.user_register(
        username='foobar', email_address='foobar@example.com', password='s3cr37'
    )
    def test_token_creation(self, user):
        response = self._post_token(user['username'], 's3cr37')
        assert_that(
            response,
            has_entries(
                token=uuid_(),
                auth_id=user['uuid'],
                xivo_user_uuid=user['uuid'],  # For API compatibility reason
                acl=has_item('default.user.policy'),
                session_uuid=uuid_(),
                metadata=has_entries(pbx_user_uuid=user['uuid']),
            ),
        )

        assert_http_error(
            401,
            self._post_token,
            user['username'],
            'not-our-password',
        )
        assert_http_error(
            401,
            self._post_token,
            'not-foobar',
            's3cr37',
        )

    @fixtures.http.tenant(uuid=NEW_TENANT_UUID, default_authentication_method='saml')
    @fixtures.http.user(
        username='u1',
        authentication_method='ldap',
        tenant_uuid=NEW_TENANT_UUID,
    )
    @fixtures.http.user(
        username='u2',
        authentication_method='default',
        tenant_uuid=NEW_TENANT_UUID,
    )
    def test_wrong_authentication_method(self, tenant, u1, u2):
        # u1 uses ldap not native
        assert_http_error(
            401,
            self._post_token,
            'u1',
            u1['password'],
        )
        # u2 uses saml (from the tenant) not native
        assert_http_error(
            401,
            self._post_token,
            'u2',
            u2['password'],
        )

        tenant['default_authentication_method'] = 'native'
        self.client.tenants.edit(tenant['uuid'], **tenant)

        # u1 uses ldap not native
        assert_http_error(
            401,
            self._post_token,
            'u1',
            u1['password'],
        )
        # u2 now uses native from the tenant
        response = self._post_token('u2', u2['password'])
        assert_that(response, has_entries(token=uuid_()))

        u1['authentication_method'] = 'native'
        self.client.users.edit(u1['uuid'], **u1)

        # u1 now uses native
        response = self._post_token('u1', u1['password'])
        assert_that(response, has_entries(token=uuid_()))

    @fixtures.http.tenant()
    # extra tenant: "master" tenant
    @fixtures.http.user(username='foobar')
    def test_token_metadata(self, tenant, user):
        top_tenant = self.get_top_tenant()

        token_data = self._post_token(user['username'], user['password'])

        assert_that(
            token_data['metadata'],
            has_entries(
                xivo_uuid='the-predefined-xivo-uuid',
                uuid=user['uuid'],
                tenant_uuid=top_tenant['uuid'],
            ),
        )

    def test_no_password(self):
        user = self.client.users.new(
            username='foobar', email_address='foobar@example.com'
        )
        try:
            assert_http_error(401, self._post_token, user['username'], 'p45sw0rd')
        finally:
            self.client.users.delete(user['uuid'])
