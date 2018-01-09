# -*- coding: utf-8 -*-
# Copyright 2015-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    equal_to,
    has_entries,
)
from xivo_test_helpers.hamcrest.uuid_ import uuid_
from .helpers import fixtures
from .helpers.base import assert_http_error, MockBackendTestCase, UNKNOWN_UUID


class TestTenants(MockBackendTestCase):

    @fixtures.http_tenant(name='foobar')
    @fixtures.http_tenant()
    def test_post(self, other, foobar):
        assert_that(other, has_entries(uuid=uuid_(), name=None))
        assert_that(foobar, has_entries(uuid=uuid_(), name='foobar'))

    @fixtures.http_tenant()
    def test_delete(self, tenant):
        self.client.tenants.delete(tenant['uuid'])

        assert_http_error(404, self.client.tenants.delete, tenant['uuid'])

    @fixtures.http_tenant()
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
    def test_put(self, tenant):
        name = 'foobar'
        body = dict(name=name)

        assert_http_error(400, self.client.tenants.edit, tenant['uuid'], name=False)
        assert_http_error(404, self.client.tenants.edit, UNKNOWN_UUID, **body)

        result = self.client.tenants.edit(tenant['uuid'], **body)

        assert_that(result, has_entries(uuid=tenant['uuid'], **body))
