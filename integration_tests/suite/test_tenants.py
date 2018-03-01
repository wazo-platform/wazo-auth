# -*- coding: utf-8 -*-
# Copyright 2015-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from __future__ import unicode_literals

from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    equal_to,
    has_entries,
)
from xivo_test_helpers.hamcrest.uuid_ import uuid_
from .helpers import fixtures
from .helpers.base import ADDRESS_NULL, assert_http_error, MockBackendTestCase, UNKNOWN_UUID

ADDRESS_1 = {
    'line_1': 'Here',
    'city': 'Québec',
    'state': 'Québec',
    'country': 'Canada',
    'zip_code': 'H0H 0H0',
}
PHONE_1 = '555-555-5555'


class TestTenants(MockBackendTestCase):

    @fixtures.http_tenant(name='foobar', address=ADDRESS_1, phone=PHONE_1)
    @fixtures.http_tenant()
    def test_post(self, other, foobar):
        assert_that(other, has_entries(
            uuid=uuid_(),
            name=None,
            address=has_entries(**ADDRESS_NULL)))

        assert_that(foobar, has_entries(
            uuid=uuid_(),
            name='foobar',
            phone=PHONE_1,
            address=has_entries(**ADDRESS_1)))

        assert_http_error(404, self.client.tenants.new, contact=UNKNOWN_UUID)

    @fixtures.http_tenant()
    def test_delete(self, tenant):
        self.client.tenants.delete(tenant['uuid'])

        assert_http_error(404, self.client.tenants.delete, tenant['uuid'])

    @fixtures.http_tenant(address=ADDRESS_1)
    def test_get_one(self, tenant):
        result = self.client.tenants.get(tenant['uuid'])

        assert_that(result, equal_to(tenant))

        assert_http_error(404, self.client.tenants.get, UNKNOWN_UUID)

    @fixtures.http_tenant(name='foobar')
    @fixtures.http_tenant(name='foobaz')
    @fixtures.http_tenant(name='foobarbaz')
    def test_list(self, foobarbaz, foobaz, foobar):
        def then(result, total=3, filtered=3, item_matcher=contains()):
            assert_that(result, has_entries(items=item_matcher, total=total, filtered=filtered))

        result = self.client.tenants.list()
        matcher = contains_inanyorder(foobaz, foobar, foobarbaz)
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
        matcher = contains(foobaz, foobarbaz, foobar)
        then(result, item_matcher=matcher)

        assert_http_error(400, self.client.tenants.list, limit='foo')
        assert_http_error(400, self.client.tenants.list, offset=-1)

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

        assert_http_error(400, self.client.tenants.edit, tenant['uuid'], name=False)
        assert_http_error(404, self.client.tenants.edit, UNKNOWN_UUID, **body)
        assert_http_error(404, self.client.tenants.edit, tenant['uuid'], **body_with_unknown_contact)

        result = self.client.tenants.edit(tenant['uuid'], **body)

        assert_that(result, has_entries(
            uuid=tenant['uuid'],
            name=name,
            contact=user['uuid'],
            address=has_entries(**ADDRESS_1)))
