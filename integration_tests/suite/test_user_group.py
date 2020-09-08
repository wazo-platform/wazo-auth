# Copyright 2017-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from functools import partial
from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    has_entries,
    has_items,
    not_,
)
from .helpers import base, fixtures
from .helpers.base import assert_http_error, assert_no_error, assert_sorted
from .helpers.constants import UNKNOWN_UUID, NB_DEFAULT_GROUPS


class TestGroupUserList(base.WazoAuthTestCase):
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
        expected = contains(self.bar, self.baz)
        assert_that(result, has_entries(total=3, filtered=3, items=expected))


class TestUserGroupList(base.WazoAuthTestCase):
    def setUp(self):
        super().setUp()
        self.foo = self.client.groups.new(name='group-foo')
        self.bar = self.client.groups.new(name='group-bar')
        self.baz = self.client.groups.new(name='group-baz')
        self.total = 3 + NB_DEFAULT_GROUPS
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
                items=contains(self.bar, self.baz),
            ),
        )


class TestUserGroupAssociation(base.WazoAuthTestCase):
    @fixtures.http.user_register()
    @fixtures.http.user_register()
    @fixtures.http.group()
    def test_delete(self, group, user1, user2):
        action = self.client.groups.remove_user

        self.client.groups.add_user(group['uuid'], user1['uuid'])
        self.client.groups.add_user(group['uuid'], user2['uuid'])

        assert_http_error(404, action, UNKNOWN_UUID, user1['uuid'])
        assert_http_error(404, action, group['uuid'], UNKNOWN_UUID)
        assert_no_error(action, group['uuid'], user2['uuid'])
        assert_no_error(action, group['uuid'], user2['uuid'])  # Twice

        result = self.client.groups.get_users(group['uuid'])
        assert_that(result, has_entries('items', contains_inanyorder(user1)))

        with self.client_in_subtenant() as (client, user3, _):
            action = client.groups.remove_user

            self.client.groups.add_user(group['uuid'], user3['uuid'])

            # group not visible to this sub tenant
            assert_http_error(404, action, group['uuid'], user3['uuid'])

            # user not visible to this sub tenant can be deleted
            with self.group(client, name='foo') as visible_group:
                self.client.groups.add_user(visible_group['uuid'], user1['uuid'])
                assert_no_error(action, visible_group['uuid'], user1['uuid'])

    @fixtures.http.user_register()
    @fixtures.http.user_register()
    @fixtures.http.group()
    def test_put(self, group, user1, user2):
        action = self.client.groups.add_user

        assert_http_error(404, action, UNKNOWN_UUID, user1['uuid'])
        assert_http_error(404, action, group['uuid'], UNKNOWN_UUID)
        assert_no_error(action, group['uuid'], user1['uuid'])
        assert_no_error(action, group['uuid'], user1['uuid'])  # Twice

        result = self.client.groups.get_users(group['uuid'])
        assert_that(result, has_entries('items', contains_inanyorder(user1)))

        with self.client_in_subtenant() as (client, user3, __):
            action = client.groups.add_user

            # group not visible to this sub tenant
            assert_http_error(404, action, group['uuid'], user3['uuid'])

            # user not visible to this sub tenant
            with self.group(client, name='foo') as visible_group:
                assert_http_error(404, action, visible_group['uuid'], user1['uuid'])

                assert_no_error(action, visible_group['uuid'], user3['uuid'])

    @fixtures.http.user_register(username='foo', password='bar')
    @fixtures.http.group(name='two')
    @fixtures.http.group(name='one')
    @fixtures.http.policy(
        name='main',
        acl_templates=[
            '{% for group in groups %}main.{{ group.name }}.*:{% endfor %}',
            '{% for group in groups %}main.{{ group.uuid }}:{% endfor %}',
        ],
    )
    def test_generated_acl(self, policy, group_1, group_2, user):
        self.client.groups.add_user(group_1['uuid'], user['uuid'])
        self.client.groups.add_user(group_2['uuid'], user['uuid'])
        self.client.users.add_policy(user['uuid'], policy['uuid'])

        user_client = self.new_auth_client('foo', 'bar')

        expected_acls = [
            'main.one.*',
            'main.two.*',
            'main.{}'.format(group_1['uuid']),
            'main.{}'.format(group_2['uuid']),
        ]
        token_data = user_client.token.new('wazo_user', expiration=5)
        assert_that(token_data, has_entries('acls', has_items(*expected_acls)))
