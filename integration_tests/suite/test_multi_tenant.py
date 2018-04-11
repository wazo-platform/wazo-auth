# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    has_entries,
)
from helpers.base import WazoAuthTestCase, assert_http_error
from .helpers import fixtures


class TestMultiTenant(WazoAuthTestCase):

    asset = 'mock_backend'

    def test_given_user_in_new_tenant_when_create_user_then_creation_allowed(self):
        creator_user = self.admin_client.users.new(username='creator', password='opensesame')
        auth_policy = self.admin_client.policies.new(name='auth-allowed', acl_templates=['auth.#'])
        self.admin_client.users.add_policy(creator_user['uuid'], auth_policy['uuid'])
        creator_client = self.new_auth_client(username='creator', password='opensesame')
        creator_token = creator_client.token.new(backend='wazo_user')
        creator_client.set_token(creator_token['token'])
        created_tenant = creator_client.tenants.new(name='created-tenant')

        created_user = creator_client.users.new(username='created-user', password='opensesame', tenant_uuid=created_tenant['uuid'])

        assert_that(created_user, has_entries(username='created-user'))

    @fixtures.http_user(username='foo')
    @fixtures.http_user(username='bar')
    @fixtures.http_user(username='baz')
    @fixtures.http_admin_client(tenant_name='test-tenant', username='created-user')
    def test_filtering_of_the_get_result(self, client, *users):
        # Only the user querying is in the tenant not foo, bar, baz
        assert_that(
            client.users.list(),
            has_entries(
                items=contains(has_entries(username='created-user')),
                total=1,
                filtered=1,
            ),
        )

        # Use the Wazo-Tenant header to filter
        tenant_uuid = self.admin_client.tenants.list(name='test-tenant')['items'][0]['uuid']
        assert_http_error(401, self.admin_client.users.list, tenant_uuid=tenant_uuid)

        # List without the tenant
        assert_that(
            self.admin_client.users.list(),
            has_entries(
                items=contains_inanyorder(
                    has_entries(username='foo'),
                    has_entries(username='bar'),
                    has_entries(username='baz'),
                ),
                total=3,
                filtered=3,
            ),
        )
