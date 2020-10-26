# Copyright 2017-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from functools import partial

from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    equal_to,
    has_entries,
    has_items,
    not_,
)
from mock import ANY
from .helpers import base, fixtures
from .helpers.constants import UNKNOWN_UUID, NB_DEFAULT_GROUPS


class TestGroups(base.WazoAuthTestCase):

    invalid_bodies = [{}, {'name': None}, {'name': 42}, {'not name': 'foobar'}]

    @fixtures.http.group(name='foobar')
    @fixtures.http.group(name='all-users-group', system_managed=True)
    def test_delete(self, all_users_group, foobar):
        base.assert_http_error(404, self.client.groups.delete, UNKNOWN_UUID)

        with self.client_in_subtenant() as (client, _, __):
            base.assert_http_error(404, client.groups.delete, foobar['uuid'])

        base.assert_no_error(self.client.groups.delete, foobar['uuid'])

        base.assert_http_error(403, self.client.groups.delete, all_users_group['uuid'])

    @fixtures.http.group(name='foobar')
    def test_get(self, foobar):
        action = self.client.groups.get

        base.assert_http_error(404, action, UNKNOWN_UUID)

        with self.client_in_subtenant() as (client, _, __):
            base.assert_http_error(404, client.groups.get, foobar['uuid'])

        result = action(foobar['uuid'])
        assert_that(result, equal_to(foobar))

    @fixtures.http.tenant(uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='foobar')
    @fixtures.http.group(name='foobaz', tenant_uuid=base.SUB_TENANT_UUID)
    def test_post(self, foobaz, foobar, _):
        assert_that(
            foobar,
            has_entries(uuid=ANY, name='foobar', tenant_uuid=self.top_tenant_uuid),
        )
        assert_that(foobaz, has_entries(tenant_uuid=base.SUB_TENANT_UUID))

        for body in self.invalid_bodies:
            base.assert_http_error(400, self.client.groups.new, **body)

        base.assert_http_error(409, self.client.groups.new, name='foobar')

    @fixtures.http.group(name='foobar')
    @fixtures.http.group(name='duplicate')
    @fixtures.http.group(name='all-users-group', system_managed=True)
    def test_put(self, all_users_group, duplicate, group):
        base.assert_http_error(
            404, self.client.groups.edit, UNKNOWN_UUID, name='foobaz'
        )

        with self.client_in_subtenant() as (client, _, __):
            base.assert_http_error(
                404, client.groups.edit, group['uuid'], name='foobaz'
            )

            # 404 should be returned before validating the body
            base.assert_http_error(404, client.groups.edit, group['uuid'], name=42)

        base.assert_http_error(
            409, self.client.groups.edit, duplicate['uuid'], name='foobar'
        )

        for body in self.invalid_bodies:
            base.assert_http_error(400, self.client.groups.edit, group['uuid'], **body)

        result = self.client.groups.edit(group['uuid'], name='foobaz')
        assert_that(result, has_entries('uuid', group['uuid'], 'name', 'foobaz'))

        result = self.client.groups.get(group['uuid'])
        assert_that(result, has_entries('uuid', group['uuid'], 'name', 'foobaz'))

        base.assert_http_error(
            403,
            self.client.groups.edit,
            all_users_group['uuid'],
            name='another name',
        )

    @fixtures.http.tenant(uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='one', tenant_uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='two', tenant_uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='three', tenant_uuid=base.SUB_TENANT_UUID)
    def test_list_tenant_filtering(self, three, two, one, _):
        action = self.client.groups.list

        # Different tenant
        response = action(tenant_uuid=self.top_tenant_uuid)
        assert_that(
            response,
            has_entries(
                total=0 + NB_DEFAULT_GROUPS,
                filtered=0 + NB_DEFAULT_GROUPS,
                items=not_(has_items(one, two, three)),
            ),
        )

        # Different tenant with recurse
        response = action(recurse=True, tenant_uuid=self.top_tenant_uuid)
        assert_that(response, has_entries(items=has_items(one, two, three)))

        # Same tenant
        response = action(tenant_uuid=base.SUB_TENANT_UUID)
        assert_that(
            response,
            has_entries(total=3 + NB_DEFAULT_GROUPS, items=has_items(one, two, three)),
        )

        with self.client_in_subtenant() as (client, _, sub_tenant):
            four = client.groups.new(name='four')

            response = action(tenant_uuid=sub_tenant['uuid'])
            assert_that(
                response,
                has_entries(
                    total=1 + NB_DEFAULT_GROUPS,
                    filtered=1 + NB_DEFAULT_GROUPS,
                    items=has_items(four),
                ),
            )
            assert_that(response, has_entries(items=not_(has_items(one, two, three))))

    @fixtures.http.tenant(uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='one', tenant_uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='two', tenant_uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='three', tenant_uuid=base.SUB_TENANT_UUID)
    def test_list_paginating(self, three, two, one, _):
        action = partial(
            self.client.groups.list, tenant_uuid=base.SUB_TENANT_UUID, order='name'
        )

        response = action(limit=1)
        assert_that(
            response,
            has_entries(
                total=3 + NB_DEFAULT_GROUPS,
                filtered=3 + NB_DEFAULT_GROUPS,
                items=has_items(one),
            ),
        )
        assert_that(response, has_entries(items=not_(has_items(two, three))))

        response = action(offset=1)
        assert_that(
            response,
            has_entries(
                total=3 + NB_DEFAULT_GROUPS,
                filtered=3 + NB_DEFAULT_GROUPS,
                items=has_items(three, two),
            ),
        )
        assert_that(response, has_entries(items=not_(has_items(one))))

    @fixtures.http.tenant(uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='group-12-one', tenant_uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='group-12-two', tenant_uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='three', tenant_uuid=base.SUB_TENANT_UUID)
    def test_list_searching(self, three, two, one, _):
        action = partial(self.client.groups.list, tenant_uuid=base.SUB_TENANT_UUID)

        response = action(search='group-12-one')
        assert_that(
            response,
            has_entries(
                total=3 + NB_DEFAULT_GROUPS,
                filtered=1,
                items=contains(one),
            ),
        )

        response = action(search='group-12')
        assert_that(
            response,
            has_entries(
                total=3 + NB_DEFAULT_GROUPS,
                filtered=2,
                items=contains_inanyorder(one, two),
            ),
        )

        response = action(name='three')
        assert_that(
            response,
            has_entries(
                total=3 + NB_DEFAULT_GROUPS,
                filtered=1,
                items=contains(three),
            ),
        )

        # default group should be excluded
        response = action(system_managed=False)
        assert_that(
            response,
            has_entries(
                total=3 + NB_DEFAULT_GROUPS,
                filtered=3,
                items=contains_inanyorder(one, two, three),
            ),
        )

    @fixtures.http.tenant(uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='one', tenant_uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='two', tenant_uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='three', tenant_uuid=base.SUB_TENANT_UUID)
    def test_list_sorting(self, three, two, one, _):
        action = partial(self.client.groups.list, tenant_uuid=base.SUB_TENANT_UUID)
        autocreated_group = self.client.groups.list(
            name='wazo-all-users-tenant-{}'.format(base.SUB_TENANT_UUID),
            tenant_uuid=base.SUB_TENANT_UUID,
        )['items'][0]
        expected = [one, three, two, autocreated_group]
        base.assert_sorted(action, order='name', expected=expected)
