# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    has_entries,
    has_items,
)
from .helpers import base, fixtures


class TestTenantUserAssociation(base.MockBackendTestCase):

    unknown_uuid = '00000000-0000-0000-0000-000000000000'

    @fixtures.http_user_register(username='bar')
    @fixtures.http_user_register(username='foo')
    @fixtures.http_tenant()
    def test_delete(self, tenant, foo, bar):
        base.assert_no_error(self.client.tenants.remove_user, tenant['uuid'], foo['uuid'])

        self.client.tenants.add_user(tenant['uuid'], foo['uuid'])
        self.client.tenants.add_user(tenant['uuid'], bar['uuid'])

        base.assert_http_error(404, self.client.tenants.remove_user, self.unknown_uuid, foo['uuid'])
        base.assert_http_error(404, self.client.tenants.remove_user, tenant['uuid'], self.unknown_uuid)
        base.assert_no_error(self.client.tenants.remove_user, tenant['uuid'], foo['uuid'])

        result = self.client.tenants.get_users(tenant['uuid'])
        assert_that(result, has_entries('items', contains_inanyorder(
            has_entries('username', 'bar'),
        )))

    @fixtures.http_user_register(username='bar')
    @fixtures.http_user_register(username='foo')
    @fixtures.http_tenant()
    def test_put(self, tenant, foo, bar):
        base.assert_http_error(404, self.client.tenants.add_user, self.unknown_uuid, foo['uuid'])
        base.assert_http_error(404, self.client.tenants.add_user, tenant['uuid'], self.unknown_uuid)
        base.assert_no_error(self.client.tenants.add_user, tenant['uuid'], foo['uuid'])
        base.assert_no_error(self.client.tenants.add_user, tenant['uuid'], foo['uuid'])  # twice
        base.assert_no_error(self.client.tenants.add_user, tenant['uuid'], bar['uuid'])

        result = self.client.tenants.get_users(tenant['uuid'])
        assert_that(result, has_entries('items', contains_inanyorder(
            has_entries('username', 'foo'),
            has_entries('username', 'bar'),
        )))

    @fixtures.http_tenant(name='ignored')
    @fixtures.http_tenant(name='baz')
    @fixtures.http_tenant(name='bar')
    @fixtures.http_tenant(name='foo')
    @fixtures.http_user()
    def test_tenant_list(self, user, foo, bar, baz, ignored):
        for tenant in (foo, bar, baz):
            self.client.tenants.add_user(tenant['uuid'], user['uuid'])

        result = self.client.users.get_tenants(user['uuid'])
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains_inanyorder(
                has_entries('name', 'foo'),
                has_entries('name', 'bar'),
                has_entries('name', 'baz'))))

        result = self.client.users.get_tenants(user['uuid'], search='ba')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 2,
            'items', contains_inanyorder(
                has_entries('name', 'bar'),
                has_entries('name', 'baz'))))

        result = self.client.users.get_tenants(user['uuid'], name='foo')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 1,
            'items', contains_inanyorder(
                has_entries('name', 'foo'))))

        result = self.client.users.get_tenants(user['uuid'], order='name', direction='desc')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('name', 'foo'),
                has_entries('name', 'baz'),
                has_entries('name', 'bar'))))

        result = self.client.users.get_tenants(user['uuid'], order='name', direction='desc', offset=1)
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('name', 'baz'),
                has_entries('name', 'bar'))))

        result = self.client.users.get_tenants(user['uuid'], order='name', direction='desc', limit=2)
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('name', 'foo'),
                has_entries('name', 'baz'))))

    @fixtures.http_user_register(username='ignored')
    @fixtures.http_user_register(username='baz')
    @fixtures.http_user_register(username='bar')
    @fixtures.http_user_register(username='foo')
    @fixtures.http_tenant()
    def test_user_list(self, tenant, foo, bar, baz, ignored):
        for user in (foo, bar, baz):
            self.client.tenants.add_user(tenant['uuid'], user['uuid'])

        result = self.client.tenants.get_users(tenant['uuid'])
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains_inanyorder(
                has_entries('username', 'foo'),
                has_entries('username', 'bar'),
                has_entries('username', 'baz'))))

        result = self.client.tenants.get_users(tenant['uuid'], search='ba')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 2,
            'items', contains_inanyorder(
                has_entries('username', 'bar'),
                has_entries('username', 'baz'))))

        result = self.client.tenants.get_users(tenant['uuid'], username='foo')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 1,
            'items', contains_inanyorder(
                has_entries('username', 'foo'))))

        result = self.client.tenants.get_users(tenant['uuid'], order='username', direction='desc')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('username', 'foo'),
                has_entries('username', 'baz'),
                has_entries('username', 'bar'))))

        result = self.client.tenants.get_users(tenant['uuid'], order='username', direction='desc', offset=1)
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('username', 'baz'),
                has_entries('username', 'bar'))))

        result = self.client.tenants.get_users(tenant['uuid'], order='username', direction='desc', limit=2)
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('username', 'foo'),
                has_entries('username', 'baz'))))

    @fixtures.http_user_register(username='foo', password='bar')
    @fixtures.http_tenant(name='two')
    @fixtures.http_tenant(name='one')
    @fixtures.http_policy(name='main', acl_templates=[
        '{% for tenant in tenants %}\nmain.{{ tenant.name }}.*\n{% endfor %}',
        '{% for tenant in tenants %}\nmain.{{ tenant.uuid }}\n{% endfor %}',
    ])
    def test_generated_acl(self, policy, tenant_1, tenant_2, user):
        self.client.tenants.add_user(tenant_1['uuid'], user['uuid'])
        self.client.tenants.add_user(tenant_2['uuid'], user['uuid'])
        self.client.users.add_policy(user['uuid'], policy['uuid'])

        user_client = self.new_auth_client('foo', 'bar')

        expected_acls = [
            'main.one.*',
            'main.two.*',
            'main.{}'.format(tenant_1['uuid']),
            'main.{}'.format(tenant_2['uuid']),
        ]
        token_data = user_client.token.new('wazo_user', expiration=5)
        assert_that(token_data, has_entries('acls', has_items(*expected_acls)))
