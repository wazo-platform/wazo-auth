# -*- coding: utf-8 -*-
# Copyright 2015-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from functools import partial
from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    equal_to,
    has_entries,
)
from xivo_test_helpers.hamcrest.uuid_ import uuid_
from .helpers import fixtures
from .helpers.base import (
    ADDRESS_NULL,
    assert_http_error,
    assert_no_error,
    assert_sorted,
    WazoAuthTestCase,
    UNKNOWN_UUID,
    SUB_TENANT_UUID,
)

ADDRESS_1 = {
    'line_1': 'Here',
    'city': 'Québec',
    'state': 'Québec',
    'country': 'Canada',
    'zip_code': 'H0H 0H0',
}
PHONE_1 = '555-555-5555'


class TestTenants(WazoAuthTestCase):

    @fixtures.http_tenant(name='foobar', address=ADDRESS_1, phone=PHONE_1)
    @fixtures.http_tenant(uuid='6668ca15-6d9e-4000-b2ec-731bc7316767', name='foobaz')
    @fixtures.http_tenant()
    def test_post(self, other, foobaz, foobar):
        assert_that(other, has_entries(
            uuid=uuid_(),
            name=None,
            parent_uuid=self.top_tenant_uuid,
            address=has_entries(**ADDRESS_NULL),
        ))

        assert_that(foobaz, has_entries(
            uuid='6668ca15-6d9e-4000-b2ec-731bc7316767',
            name='foobaz',
            parent_uuid=self.top_tenant_uuid,
            address=has_entries(**ADDRESS_NULL),
        ))

        assert_that(foobar, has_entries(
            uuid=uuid_(),
            name='foobar',
            phone=PHONE_1,
            parent_uuid=self.top_tenant_uuid,
            address=has_entries(**ADDRESS_1),
        ))

        with self.tenant(self.client, name='subtenant', parent_uuid=foobar['uuid']) as subtenant:
            assert_that(subtenant, has_entries(
                uuid=uuid_(),
                name='subtenant',
                parent_uuid=foobar['uuid'],
            ))

    @fixtures.http_tenant()
    def test_delete(self, tenant):
        with self.client_in_subtenant() as (client, user, sub_tenant):
            assert_http_error(404, client.tenants.delete, tenant['uuid'])
            assert_no_error(client.tenants.delete, sub_tenant['uuid'])

        assert_no_error(self.client.tenants.delete, tenant['uuid'])
        assert_http_error(404, self.client.tenants.delete, tenant['uuid'])

    @fixtures.http_tenant(address=ADDRESS_1)
    def test_get_one(self, tenant):
        with self.client_in_subtenant() as (client, user, sub_tenant):
            assert_http_error(404, client.tenants.get, tenant['uuid'])
            result = client.tenants.get(sub_tenant['uuid'])
            assert_that(result, equal_to(sub_tenant))

        result = self.client.tenants.get(tenant['uuid'])
        assert_that(result, equal_to(tenant))

        assert_http_error(404, self.client.tenants.get, UNKNOWN_UUID)

    @fixtures.http_tenant(name='foobar')
    @fixtures.http_tenant(name='foobaz')
    @fixtures.http_tenant(name='foobarbaz')
    # extra tenant: "master" tenant
    def test_list(self, foobarbaz, foobaz, foobar):
        top_tenant = self.get_top_tenant()

        def then(result, total=4, filtered=4, item_matcher=contains(top_tenant)):
            assert_that(result, has_entries(items=item_matcher, total=total, filtered=filtered))

        result = self.client.tenants.list()
        matcher = contains_inanyorder(foobaz, foobar, foobarbaz, top_tenant)
        then(result, item_matcher=matcher)

        result = self.client.tenants.list(uuid=foobaz['uuid'])
        matcher = contains_inanyorder(foobaz)
        then(result, filtered=1, item_matcher=matcher)

        result = self.client.tenants.list(search='bar')
        matcher = contains_inanyorder(foobar, foobarbaz)
        then(result, filtered=2, item_matcher=matcher)

        result = self.client.tenants.list(limit=1, offset=1, order='name')
        matcher = contains(foobarbaz)
        then(result, item_matcher=matcher)

        result = self.client.tenants.list(order='name', direction='desc')
        matcher = contains(top_tenant, foobaz, foobarbaz, foobar)
        then(result, item_matcher=matcher)

        assert_http_error(400, self.client.tenants.list, limit='foo')
        assert_http_error(400, self.client.tenants.list, offset=-1)

        with self.client_in_subtenant() as (client, user, sub_tenant):
            with self.tenant(client, name='subsub') as subsub:
                result = client.tenants.list()
                matcher = contains(sub_tenant, subsub)
                then(result, total=2, filtered=2, item_matcher=matcher)

    @fixtures.http_tenant()
    @fixtures.http_user()
    def test_put(self, user, tenant):
        name = 'foobar'
        body = {
            'name': name,
            'address': ADDRESS_1,
            'contact': user['uuid'],
        }
        body_with_unknown_contact = dict(body)
        body_with_unknown_contact['contact'] = UNKNOWN_UUID

        with self.client_in_subtenant() as (client, _, sub_tenant):
            assert_http_error(404, client.tenants.edit, tenant['uuid'], **body)
            assert_no_error(client.tenants.edit, sub_tenant['uuid'], **body)

        assert_http_error(400, self.client.tenants.edit, tenant['uuid'], name=False)
        assert_http_error(404, self.client.tenants.edit, UNKNOWN_UUID, **body)
        assert_http_error(404, self.client.tenants.edit, tenant['uuid'], **body_with_unknown_contact)

        result = self.client.tenants.edit(tenant['uuid'], **body)

        assert_that(result, has_entries(
            uuid=tenant['uuid'],
            name=name,
            contact=user['uuid'],
            address=has_entries(**ADDRESS_1)))


class TestTenantPolicyAssociation(WazoAuthTestCase):

    @fixtures.http_tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='foo', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='bar', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='baz', tenant_uuid=SUB_TENANT_UUID)
    def test_policy_list(self, baz, bar, foo, _):
        assert_http_error(404, self.client.tenants.get_policies, UNKNOWN_UUID)
        with self.client_in_subtenant(parent_uuid=SUB_TENANT_UUID) as (client, _, sub_tenant):
            assert_http_error(404, client.tenants.get_policies, SUB_TENANT_UUID)

        action = partial(self.client.tenants.get_policies, SUB_TENANT_UUID)

        result = action()
        expected = contains_inanyorder(*[has_entries(name=n) for n in ('foo', 'bar', 'baz')])
        assert_that(result, has_entries(total=3, filtered=3, items=expected))

        result = action(search='ba')
        expected = contains_inanyorder(has_entries(name='bar'), has_entries(name='baz'))
        assert_that(result, has_entries(total=3, filtered=2, items=expected))

    @fixtures.http_tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='foo', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='bar', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='baz', tenant_uuid=SUB_TENANT_UUID)
    def test_policy_list_sorting(self, baz, bar, foo, _):
        action = partial(self.client.tenants.get_policies, SUB_TENANT_UUID)

        expected = [has_entries(name='bar'), has_entries(name='baz'), has_entries(name='foo')]
        assert_sorted(action, order='name', expected=expected)

    @fixtures.http_tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='foo', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='bar', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='baz', tenant_uuid=SUB_TENANT_UUID)
    def test_list_paginating(self, baz, bar, foo, _):
        action = partial(self.client.tenants.get_policies, SUB_TENANT_UUID, order='name', direction='asc')

        result = action(offset=1)
        expected = contains(has_entries(name='baz'), has_entries(name='foo'))
        assert_that(result, has_entries(total=3, filtered=3, items=expected))

        result = action(limit=2)
        expected = contains(has_entries(name='bar'), has_entries(name='baz'))
        assert_that(result, has_entries(total=3, filtered=3, items=expected))
