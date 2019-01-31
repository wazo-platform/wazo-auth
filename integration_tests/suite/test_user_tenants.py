# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    has_entries,
)
from .helpers.base import (
    assert_http_error,
    UNKNOWN_UUID,
    WazoAuthTestCase,
)


class TestUserTenant(WazoAuthTestCase):

    def test_list(self):
        assert_http_error(404, self.client.users.get_tenants, UNKNOWN_UUID)

        with self.client_in_subtenant() as (client, user, a):
            with self.tenant(client, parent_uuid=a['uuid']) as b:
                with self.tenant(client, parent_uuid=b['uuid']) as c:
                    result = self.client.users.get_tenants(user['uuid'])
                    assert_that(
                        result,
                        has_entries(
                            total=3,
                            filtered=3,
                            items=contains_inanyorder(a, b, c),
                        )
                    )

                with self.client_in_subtenant(parent_uuid=b['uuid']) as (sub_client, _, d):
                    assert_http_error(404, sub_client.users.get_tenants, user['uuid'])


class TestTenantUser(WazoAuthTestCase):

    def test_list(self):
        assert_http_error(404, self.client.tenants.get_users, UNKNOWN_UUID)

        with self.client_in_subtenant() as (client, user, subtenant):
            assert_http_error(404, client.tenants.get_users, self.top_tenant_uuid)

            result = client.tenants.get_users(subtenant['uuid'])
            assert_that(
                result,
                has_entries(
                    total=1,
                    filtered=1,
                    items=contains(user),
                )
            )
