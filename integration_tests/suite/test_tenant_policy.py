# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    has_entries,
)
from .helpers import base, fixtures


class TestTenantPolicyAssociation(base.MockBackendTestCase):

    @fixtures.http_policy(name='bar')
    @fixtures.http_policy(name='foo')
    @fixtures.http_tenant()
    def test_delete(self, tenant, foo, bar):
        base.assert_no_error(self.client.tenants.remove_policy, tenant['uuid'], foo['uuid'])

        self.client.tenants.add_policy(tenant['uuid'], foo['uuid'])
        self.client.tenants.add_policy(tenant['uuid'], bar['uuid'])

        base.assert_http_error(404, self.client.tenants.remove_policy, base.UNKNOWN_UUID, foo['uuid'])
        base.assert_http_error(404, self.client.tenants.remove_policy, tenant['uuid'], base.UNKNOWN_UUID)
        base.assert_no_error(self.client.tenants.remove_policy, tenant['uuid'], foo['uuid'])

        result = self.client.tenants.get_policies(tenant['uuid'])
        assert_that(result, has_entries('items', contains_inanyorder(
            has_entries('name', 'bar'),
        )))

    @fixtures.http_policy(name='bar')
    @fixtures.http_policy(name='foo')
    @fixtures.http_tenant()
    def test_put(self, tenant, foo, bar):
        base.assert_http_error(404, self.client.tenants.add_policy, base.UNKNOWN_UUID, foo['uuid'])
        base.assert_http_error(404, self.client.tenants.add_policy, tenant['uuid'], base.UNKNOWN_UUID)
        base.assert_no_error(self.client.tenants.add_policy, tenant['uuid'], foo['uuid'])
        base.assert_no_error(self.client.tenants.add_policy, tenant['uuid'], foo['uuid'])  # twice
        base.assert_no_error(self.client.tenants.add_policy, tenant['uuid'], bar['uuid'])

        result = self.client.tenants.get_policies(tenant['uuid'])
        assert_that(result, has_entries('items', contains_inanyorder(
            has_entries('name', 'foo'),
            has_entries('name', 'bar'),
        )))

    @fixtures.http_tenant(name='ignored')
    @fixtures.http_tenant(name='baz')
    @fixtures.http_tenant(name='bar')
    @fixtures.http_tenant(name='foo')
    @fixtures.http_policy()
    def test_tenant_list(self, policy, foo, bar, baz, ignored):
        for tenant in (foo, bar, baz):
            self.client.tenants.add_policy(tenant['uuid'], policy['uuid'])

        result = self.client.policies.get_tenants(policy['uuid'])
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains_inanyorder(
                has_entries('name', 'foo'),
                has_entries('name', 'bar'),
                has_entries('name', 'baz'))))

        result = self.client.policies.get_tenants(policy['uuid'], search='ba')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 2,
            'items', contains_inanyorder(
                has_entries('name', 'bar'),
                has_entries('name', 'baz'))))

        result = self.client.policies.get_tenants(policy['uuid'], name='foo')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 1,
            'items', contains_inanyorder(
                has_entries('name', 'foo'))))

        result = self.client.policies.get_tenants(policy['uuid'], order='name', direction='desc')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('name', 'foo'),
                has_entries('name', 'baz'),
                has_entries('name', 'bar'))))

        result = self.client.policies.get_tenants(policy['uuid'], order='name', direction='desc', offset=1)
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('name', 'baz'),
                has_entries('name', 'bar'))))

        result = self.client.policies.get_tenants(policy['uuid'], order='name', direction='desc', limit=2)
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('name', 'foo'),
                has_entries('name', 'baz'))))

    @fixtures.http_policy(name='ignored')
    @fixtures.http_policy(name='baz')
    @fixtures.http_policy(name='bar')
    @fixtures.http_policy(name='foo')
    @fixtures.http_tenant()
    def test_policy_list(self, tenant, foo, bar, baz, ignored):
        for policy in (foo, bar, baz):
            self.client.tenants.add_policy(tenant['uuid'], policy['uuid'])

        result = self.client.tenants.get_policies(tenant['uuid'])
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains_inanyorder(
                has_entries('name', 'foo'),
                has_entries('name', 'bar'),
                has_entries('name', 'baz'))))

        result = self.client.tenants.get_policies(tenant['uuid'], search='ba')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 2,
            'items', contains_inanyorder(
                has_entries('name', 'bar'),
                has_entries('name', 'baz'))))

        result = self.client.tenants.get_policies(tenant['uuid'], name='foo')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 1,
            'items', contains_inanyorder(
                has_entries('name', 'foo'))))

        result = self.client.tenants.get_policies(tenant['uuid'], order='name', direction='desc')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('name', 'foo'),
                has_entries('name', 'baz'),
                has_entries('name', 'bar'))))

        result = self.client.tenants.get_policies(tenant['uuid'], order='name', direction='desc', offset=1)
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('name', 'baz'),
                has_entries('name', 'bar'))))

        result = self.client.tenants.get_policies(tenant['uuid'], order='name', direction='desc', limit=2)
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('name', 'foo'),
                has_entries('name', 'baz'))))
