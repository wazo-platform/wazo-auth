# Copyright 2017-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from functools import partial
from unittest.mock import ANY

from hamcrest import (
    assert_that,
    contains_exactly,
    contains_inanyorder,
    equal_to,
    has_entries,
    has_items,
    has_length,
    not_,
    starts_with,
)
from .helpers import base, fixtures
from .helpers.constants import (
    UNKNOWN_UUID,
    NB_DEFAULT_GROUPS,
    NB_DEFAULT_GROUPS_NOT_READONLY,
)


@base.use_asset('base')
class TestGroups(base.APIIntegrationTest):

    invalid_bodies = [{}, {'name': None}, {'name': 42}, {'not name': 'foobar'}]

    @fixtures.http.group(name='foobar')
    @fixtures.http.group(name='all-users-group', read_only=True)
    def test_delete(self, foobar, all_users_group):
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

    @fixtures.http.group(name='dup')
    def test_post_duplicate_name(self, _):
        base.assert_http_error(409, self.client.groups.new, name='dup')

    @fixtures.http.group(slug='dup')
    def test_post_duplicate_slug(self, _):
        base.assert_http_error(409, self.client.groups.new, name='dup', slug='dup')

    @fixtures.http.group(slug='first')
    def test_post_generate_slug(self, _):
        with self.group(self.client, name='first') as group:
            assert_that(group, has_entries(slug=has_length(3)))

    @fixtures.http.tenant(uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='first', slug='first', tenant_uuid=base.SUB_TENANT_UUID)
    def test_post_generate_slug_other_tenant(self, _, __):
        with self.group(self.client, name='first') as group:
            assert_that(group, has_entries(slug='first'))

    @fixtures.http.tenant(uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='foobar')
    @fixtures.http.group(name='foobaz', tenant_uuid=base.SUB_TENANT_UUID)
    def test_post(self, _, foobar, foobaz):
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
    @fixtures.http.group(name='all-users-group', read_only=True)
    def test_put(self, group, duplicate, all_users_group):
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

    @fixtures.http.group(slug='ABC')
    def test_put_slug_is_read_only(self, group):
        new_body = dict(group)
        new_body['slug'] = 'DEF'

        result = self.client.groups.edit(group['uuid'], **new_body)

        assert_that(result, has_entries(**group))

    @fixtures.http.tenant(uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='one', tenant_uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='two', tenant_uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='three', tenant_uuid=base.SUB_TENANT_UUID)
    def test_list_tenant_filtering(self, _, one, two, three):
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

        # Parent tenant with recurse
        response = action(recurse=True, tenant_uuid=self.top_tenant_uuid)
        assert_that(response, has_entries(items=has_items(one, two, three)))

        # Same tenant
        response = action(tenant_uuid=base.SUB_TENANT_UUID)
        assert_that(
            response,
            has_entries(total=3 + NB_DEFAULT_GROUPS, items=has_items(one, two, three)),
        )

        # Another tenant
        with self.client_in_subtenant() as (client, _, sub_tenant):
            four = client.groups.new(name='four')
            default_groups = [
                has_entries(name=starts_with('wazo')),
            ] * NB_DEFAULT_GROUPS

            response = action(tenant_uuid=sub_tenant['uuid'])
            assert_that(
                response,
                has_entries(
                    total=1 + NB_DEFAULT_GROUPS,
                    filtered=1 + NB_DEFAULT_GROUPS,
                    items=contains_inanyorder(four, *default_groups),
                ),
            )

    @fixtures.http.tenant(uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='one', tenant_uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='two', tenant_uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='three', tenant_uuid=base.SUB_TENANT_UUID)
    def test_list_paginating(self, _, one, two, three):
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
    def test_list_searching(self, _, one, two, three):
        action = partial(self.client.groups.list, tenant_uuid=base.SUB_TENANT_UUID)

        response = action(search='group-12-one')
        assert_that(
            response,
            has_entries(
                total=3 + NB_DEFAULT_GROUPS,
                filtered=1,
                items=contains_exactly(one),
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
                items=contains_exactly(three),
            ),
        )

        # all-users group should be excluded
        admin_group = has_entries(name='wazo_default_admin_group')
        response = action(read_only=False)
        assert_that(
            response,
            has_entries(
                total=3 + NB_DEFAULT_GROUPS,
                filtered=3 + NB_DEFAULT_GROUPS_NOT_READONLY,
                items=contains_inanyorder(one, two, three, admin_group),
            ),
        )

    @fixtures.http.tenant(uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='one', tenant_uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='two', tenant_uuid=base.SUB_TENANT_UUID)
    @fixtures.http.group(name='three', tenant_uuid=base.SUB_TENANT_UUID)
    def test_list_sorting(self, _, one, two, three):
        action = partial(self.client.groups.list, tenant_uuid=base.SUB_TENANT_UUID)
        all_users_group = self.client.groups.list(
            name=f'wazo-all-users-tenant-{base.SUB_TENANT_UUID}',
            tenant_uuid=base.SUB_TENANT_UUID,
        )['items'][0]
        admins_group = self.client.groups.list(
            name='wazo_default_admin_group',
            tenant_uuid=base.SUB_TENANT_UUID,
        )['items'][0]
        expected = [one, three, two, all_users_group, admins_group]
        base.assert_sorted(action, order='name', expected=expected)

    @fixtures.http.group(groupname='visible')
    @fixtures.http.group(groupname='hidden')
    @fixtures.http.policy()
    def test_list_filter_policy(self, group, group_hidden, group_policy):
        self.client.groups.add_policy(group['uuid'], group_policy['uuid'])

        response = self.client.groups.list(policy_uuid=group_policy['uuid'])
        assert_that(
            response,
            has_entries(
                total=2 + NB_DEFAULT_GROUPS,
                filtered=1,
                items=contains_inanyorder(group),
            ),
        )
        response = self.client.groups.list(policy_slug=group_policy['slug'])
        assert_that(
            response,
            has_entries(
                total=2 + NB_DEFAULT_GROUPS,
                filtered=1,
                items=contains_inanyorder(group),
            ),
        )

    @fixtures.http.tenant(uuid=base.SUB_TENANT_UUID)
    def test_default_groups(self, _):
        # assert existence in master tenant
        response = self.client.groups.list(tenant_uuid=self.top_tenant_uuid)
        assert_that(
            response,
            has_entries(
                total=NB_DEFAULT_GROUPS,
                filtered=NB_DEFAULT_GROUPS,
                items=contains_inanyorder(
                    has_entries(slug=f'wazo-all-users-tenant-{self.top_tenant_uuid}'),
                    has_entries(slug='wazo_default_admin_group'),
                ),
            ),
        )

        # assert policies in master tenant
        admin_group_uuid = self.client.groups.list(
            tenant_uuid=self.top_tenant_uuid, slug='wazo_default_admin_group'
        )['items'][0]['uuid']
        response = self.client.groups.get_policies(
            admin_group_uuid, tenant_uuid=self.top_tenant_uuid
        )
        assert_that(
            response,
            has_entries(
                items=contains_inanyorder(has_entries(slug='wazo_default_admin_policy'))
            ),
        )

        # assert existence in subtenant
        response = self.client.groups.list(tenant_uuid=base.SUB_TENANT_UUID)
        assert_that(
            response,
            has_entries(
                total=NB_DEFAULT_GROUPS,
                filtered=NB_DEFAULT_GROUPS,
                items=contains_inanyorder(
                    has_entries(slug=f'wazo-all-users-tenant-{base.SUB_TENANT_UUID}'),
                    has_entries(slug='wazo_default_admin_group'),
                ),
            ),
        )
        # assert policies in subtenant
        admin_group_uuid = self.client.groups.list(
            tenant_uuid=base.SUB_TENANT_UUID, slug='wazo_default_admin_group'
        )['items'][0]['uuid']
        response = self.client.groups.get_policies(
            admin_group_uuid, tenant_uuid=base.SUB_TENANT_UUID
        )
        assert_that(
            response,
            has_entries(
                items=contains_inanyorder(has_entries(slug='wazo_default_admin_policy'))
            ),
        )

    @fixtures.http.tenant(uuid=base.SUB_TENANT_UUID)
    def test_default_groups_policies_are_restored_after_restart(self, _):
        admin_group_uuid = self.client.groups.list(
            tenant_uuid=base.SUB_TENANT_UUID, slug='wazo_default_admin_group'
        )['items'][0]['uuid']

        group_policies = self.client.groups.get_policies(
            admin_group_uuid, tenant_uuid=base.SUB_TENANT_UUID
        )['items']
        for group_policy in group_policies:
            self.client.groups.remove_policy(admin_group_uuid, group_policy['uuid'])

        self.restart_auth()

        response = self.client.groups.get_policies(
            admin_group_uuid, tenant_uuid=base.SUB_TENANT_UUID
        )
        assert_that(
            response,
            has_entries(
                items=contains_inanyorder(has_entries(slug='wazo_default_admin_policy'))
            ),
        )
