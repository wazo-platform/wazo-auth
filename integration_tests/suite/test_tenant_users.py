# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import requests
from hamcrest import (
    assert_that,
    calling,
    contains_inanyorder,
    has_entries,
    has_properties,
)
from xivo_test_helpers.hamcrest.raises import raises
from .helpers import base, fixtures


class TestTenantUserAssociation(base.MockBackendTestCase):

    unknown_uuid = '00000000-0000-0000-0000-000000000000'

    @fixtures.http_user(username='bar')
    @fixtures.http_user(username='foo')
    @fixtures.http_tenant()
    def test_delete(self, tenant, foo, bar):
        self.client.tenants.add_user(tenant['uuid'], foo['uuid'])
        self.client.tenants.add_user(tenant['uuid'], bar['uuid'])

        assert_http_error(404, self.client.tenants.remove_user, self.unknown_uuid, foo['uuid'])
        assert_http_error(404, self.client.tenants.remove_user, tenant['uuid'], self.unknown_uuid)
        assert_no_error(self.client.tenants.remove_user, tenant['uuid'], foo['uuid'])
        assert_http_error(404, self.client.tenants.remove_user, tenant['uuid'], foo['uuid'])  # twice

        result = self.client.tenants.get_users(tenant['uuid'])
        assert_that(result, has_entries('items', contains_inanyorder(
            has_entries('username', 'bar'),
        )))


    @fixtures.http_user(username='bar')
    @fixtures.http_user(username='foo')
    @fixtures.http_tenant()
    def test_put(self, tenant, foo, bar):
        assert_http_error(404, self.client.tenants.add_user, self.unknown_uuid, foo['uuid'])
        assert_http_error(404, self.client.tenants.add_user, tenant['uuid'], self.unknown_uuid)
        assert_no_error(self.client.tenants.add_user, tenant['uuid'], foo['uuid'])
        assert_no_error(self.client.tenants.add_user, tenant['uuid'], foo['uuid'])  # twice
        assert_no_error(self.client.tenants.add_user, tenant['uuid'], bar['uuid'])

        result = self.client.tenants.get_users(tenant['uuid'])
        assert_that(result, has_entries('items', contains_inanyorder(
            has_entries('username', 'foo'),
            has_entries('username', 'bar'),
        )))


def assert_no_error(fn, *args, **kwargs):
    return fn(*args, **kwargs)


def assert_http_error(status_code, fn, *args, **kwargs):
    assert_that(
        calling(fn).with_args(*args, **kwargs),
        raises(requests.HTTPError).matching(
            has_properties('response', has_properties('status_code', status_code))))
