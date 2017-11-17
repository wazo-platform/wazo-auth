# -*- coding: utf-8 -*-
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import requests
from hamcrest import (
    assert_that,
    calling,
    contains,
    contains_inanyorder,
    equal_to,
    has_entries,
    has_properties,
)
from xivo_test_helpers.hamcrest.raises import raises
from xivo_test_helpers.hamcrest.uuid_ import uuid_
from .helpers import fixtures
from .helpers.base import MockBackendTestCase


class TestTenants(MockBackendTestCase):

    @fixtures.http_tenant(name='foobar')
    def test_post(self, tenant):
        name = 'foobar'

        assert_that(
            tenant,
            has_entries(
                'uuid', uuid_(),
                'name', name,
            ),
        )

        assert_that(
            calling(self.client.tenants.new).with_args(name=name),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 409)),
            ),
        )

    @fixtures.http_tenant()
    def test_delete(self, tenant):
        self.client.tenants.delete(tenant['uuid'])

        assert_that(
            calling(self.client.tenants.delete).with_args(tenant['uuid']),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 404)),
            )
        )

    @fixtures.http_tenant()
    def test_get_one(self, tenant):
        result = self.client.tenants.get(tenant['uuid'])
        assert_that(result, equal_to(tenant))

        assert_that(
            calling(self.client.tenants.get).with_args('unknown-uuid'),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 404)),
            )
        )

    @fixtures.http_tenant(name='foobar')
    @fixtures.http_tenant(name='foobaz')
    @fixtures.http_tenant(name='foobarbaz')
    def test_list(self, foobarbaz, foobaz, foobar):
        result = self.client.tenants.list()
        assert_that(
            result,
            has_entries(
                'items', contains_inanyorder(
                    equal_to(foobaz),
                    equal_to(foobar),
                    equal_to(foobarbaz),
                ),
                'total', 3,
                'filtered', 3,
            ),
            'no args',
        )

        result = self.client.tenants.list(uuid=foobaz['uuid'])
        assert_that(
            result,
            has_entries(
                'items', contains_inanyorder(
                    equal_to(foobaz),
                ),
                'total', 3,
                'filtered', 1,
            ),
            'strict match',
        )

        result = self.client.tenants.list(search='bar')
        assert_that(
            result,
            has_entries(
                'items', contains_inanyorder(
                    equal_to(foobar),
                    equal_to(foobarbaz),
                ),
                'total', 3,
                'filtered', 2,
            ),
            'search',
        )

        result = self.client.tenants.list(limit=1, offset=1, order='name')
        assert_that(
            result,
            has_entries('items', contains(
                equal_to(foobarbaz),
            )),
            'limit and offset',
        )

        result = self.client.tenants.list(order='name', direction='desc')
        assert_that(
            result,
            has_entries('items', contains(
                equal_to(foobaz),
                equal_to(foobarbaz),
                equal_to(foobar),
            )),
            'sort',
        )

        assert_that(
            calling(self.client.tenants.list).with_args(limit='foo'),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 400)),
            ),
            'invalid limit',
        )
        assert_that(
            calling(self.client.tenants.list).with_args(offset=-1),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 400)),
            ),
            'invalid offset',
        )
