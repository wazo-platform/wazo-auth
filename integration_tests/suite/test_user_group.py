# Copyright 2017-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import uuid
from functools import partial

from hamcrest import (
    assert_that,
    contains_exactly,
    contains_inanyorder,
    has_entries,
    has_items,
    not_,
)

from .helpers import base, fixtures
from .helpers.base import assert_http_error, assert_no_error, assert_sorted
from .helpers.constants import NB_ALL_USERS_GROUPS, UNKNOWN_UUID

TENANT_UUID_1 = str(uuid.uuid4())
TENANT_UUID_2 = str(uuid.uuid4())


@base.use_asset('base')
class TestGroupUserList(base.APIIntegrationTest):
    def setUp(self):
        super().setUp()
        self.foo = self.client.users.new(username='foo')
        self.bar = self.client.users.new(username='bar')
        self.baz = self.client.users.new(username='baz')
        self.ignored = self.client.users.new(username='ignored')
        self.group = self.client.groups.new(name='mygroup')
        for user in (self.foo, self.bar, self.baz):
            self.client.groups.add_user(self.group['uuid'], user['uuid'])
        self.action = partial(self.client.groups.get_users, self.group['uuid'])

    def tearDown(self):
        for user in (self.foo, self.bar, self.baz, self.ignored):
            self.client.users.delete(user['uuid'])
        self.client.groups.delete(self.group['uuid'])
        super().tearDown()

    def test_list(self):
        result = self.action()
        expected = contains_inanyorder(self.foo, self.bar, self.baz)
        assert_that(result, has_entries(total=3, filtered=3, items=expected))

        result = self.action(search='ba')
        expected = contains_inanyorder(self.bar, self.baz)
        assert_that(result, has_entries(total=3, filtered=2, items=expected))

        result = self.action(username='foo')
        expected = contains_inanyorder(self.foo)
        assert_that(result, has_entries(total=3, filtered=1, items=expected))

    def test_sorting(self):
        expected = [self.bar, self.baz, self.foo]
        assert_sorted(self.action, order='username', expected=expected)

    def test_paginating(self):
        result = self.action(order='username', offset=1)
        expected = contains_inanyorder(self.baz, self.foo)
        assert_that(result, has_entries(total=3, filtered=3, items=expected))

        result = self.action(order='username', limit=2)
        expected = contains_exactly(self.bar, self.baz)
        assert_that(result, has_entries(total=3, filtered=3, items=expected))


@base.use_asset('base')
class TestUserGroupList(base.APIIntegrationTest):
    def setUp(self):
        super().setUp()
        self.foo = self.client.groups.new(name='group-foo')
        self.bar = self.client.groups.new(name='group-bar')
        self.baz = self.client.groups.new(name='group-baz')
        self.total = 3 + NB_ALL_USERS_GROUPS
        self.ignored = self.client.groups.new(name='ignored')
        self.user = self.client.users.new(username='alice')
        for group in (self.foo, self.bar, self.baz):
            self.client.groups.add_user(group['uuid'], self.user['uuid'])
        self.action = partial(self.client.users.get_groups, self.user['uuid'])

    def tearDown(self):
        self.client.users.delete(self.user['uuid'])
        for group in (self.ignored, self.baz, self.bar, self.foo):
            self.client.groups.delete(group['uuid'])
        super().tearDown()

    def test_list(self):
        result = self.action()
        expected = has_items(self.foo, self.bar, self.baz)
        assert_that(
            result,
            has_entries(total=self.total, filtered=self.total, items=expected),
        )

        result = self.action(search='group-ba')
        expected = contains_inanyorder(self.bar, self.baz)
        assert_that(result, has_entries(total=self.total, filtered=2, items=expected))

        result = self.action(name='group-foo')
        expected = contains_inanyorder(self.foo)
        assert_that(result, has_entries(total=self.total, filtered=1, items=expected))

        # user not in a visible tenant
        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(404, client.users.get_groups, self.user['uuid'])

    def test_sorting(self):
        default = self.client.groups.list(search='wazo-all-users')['items'][0]
        expected = [self.bar, self.baz, self.foo, default]
        assert_sorted(self.action, order='name', expected=expected)

    def test_pagination(self):
        result = self.action(order='name', offset=1)
        assert_that(
            result,
            has_entries(
                total=self.total,
                filtered=self.total,
                items=has_items(self.baz, self.foo),
            ),
        )
        assert_that(result, has_entries(items=has_items(not_(self.bar))))

        result = self.action(order='name', limit=2)
        assert_that(
            result,
            has_entries(
                total=self.total,
                filtered=self.total,
                items=contains_exactly(self.bar, self.baz),
            ),
        )


@base.use_asset('base')
class TestUserGroupAssociation(base.APIIntegrationTest):
    @fixtures.http.tenant(uuid=TENANT_UUID_1)
    @fixtures.http.user(tenant_uuid=TENANT_UUID_1)
    @fixtures.http.user(tenant_uuid=TENANT_UUID_1)
    @fixtures.http.group(tenant_uuid=TENANT_UUID_1)
    @fixtures.http.group(name='all-users-group', read_only=True)
    def test_delete(self, _, user1, user2, group, all_users_group):
        action = self.client.groups.remove_user

        self.client.groups.add_user(group['uuid'], user1['uuid'])
        self.client.groups.add_user(group['uuid'], user2['uuid'])

        assert_http_error(404, action, UNKNOWN_UUID, user1['uuid'])
        assert_http_error(404, action, group['uuid'], UNKNOWN_UUID)
        assert_no_error(action, group['uuid'], user2['uuid'])
        assert_no_error(action, group['uuid'], user2['uuid'])  # Twice

        assert_http_error(
            403,
            action,
            all_users_group['uuid'],
            user2['uuid'],
        )

        result = self.client.groups.get_users(group['uuid'])
        assert_that(result, has_entries(items=contains_inanyorder(user1)))

        with self.client_in_subtenant() as (client, user3, _):
            action = client.groups.remove_user

            assert_http_error(
                400, self.client.groups.add_user, group['uuid'], user3['uuid']
            )

            # group not visible to this sub tenant
            assert_http_error(404, action, group['uuid'], user3['uuid'])

            # user not visible to this sub tenant can be deleted
            with self.group(client, name='foo') as visible_group:
                assert_http_error(
                    400,
                    self.client.groups.add_user,
                    visible_group['uuid'],
                    user1['uuid'],
                )
                assert_no_error(action, visible_group['uuid'], user1['uuid'])

    @fixtures.http.tenant(uuid=TENANT_UUID_1)
    @fixtures.http.tenant(uuid=TENANT_UUID_2)
    @fixtures.http.user(tenant_uuid=TENANT_UUID_1)
    @fixtures.http.user(tenant_uuid=TENANT_UUID_2)
    @fixtures.http.group(tenant_uuid=TENANT_UUID_1)
    @fixtures.http.group(
        name='all-users-group', read_only=True, tenant_uuid=TENANT_UUID_2
    )
    def test_put(self, _, __, user1, user2, group, all_users_group):
        action = self.client.groups.add_user

        assert_http_error(404, action, UNKNOWN_UUID, user1['uuid'])
        assert_http_error(404, action, group['uuid'], UNKNOWN_UUID)
        assert_no_error(action, group['uuid'], user1['uuid'])
        assert_no_error(action, group['uuid'], user1['uuid'])  # Twice

        assert_http_error(
            403,
            action,
            all_users_group['uuid'],
            user2['uuid'],
        )

        result = self.client.groups.get_users(group['uuid'])
        assert_that(result, has_entries(items=contains_inanyorder(user1)))

        with self.client_in_subtenant() as (client, user3, __):
            action = client.groups.add_user

            # group not visible to this sub tenant
            assert_http_error(404, action, group['uuid'], user3['uuid'])

            # user not visible to this sub tenant
            with self.group(client, name='foo') as visible_group:
                assert_http_error(404, action, visible_group['uuid'], user1['uuid'])

                assert_no_error(action, visible_group['uuid'], user3['uuid'])

    @fixtures.http.tenant(uuid=TENANT_UUID_1)
    @fixtures.http.tenant(uuid=TENANT_UUID_2)
    @fixtures.http.user(tenant_uuid=TENANT_UUID_1)
    @fixtures.http.user(tenant_uuid=TENANT_UUID_2)
    @fixtures.http.group(tenant_uuid=TENANT_UUID_2)
    def test_put_user_in_group_with_mismatching_tenants_raises_400_http_error(
        self, _, __, user1, user2, group
    ):
        action = self.client.groups.add_user

        assert_http_error(400, action, group['uuid'], user1['uuid'])
        assert_no_error(action, group['uuid'], user2['uuid'])
