# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    has_entries,
    has_items,
)
from .helpers import base, fixtures


class TestUserGroupAssociation(base.MockBackendTestCase):

    @fixtures.http_user_register()
    @fixtures.http_user_register()
    @fixtures.http_group()
    def test_delete(self, group, user1, user2):
        self.client.groups.add_user(group['uuid'], user1['uuid'])
        self.client.groups.add_user(group['uuid'], user2['uuid'])

        base.assert_http_error(404, self.client.groups.remove_user, base.UNKNOWN_UUID, user1['uuid'])
        base.assert_http_error(404, self.client.groups.remove_user, group['uuid'], base.UNKNOWN_UUID)
        base.assert_no_error(self.client.groups.remove_user, group['uuid'], user2['uuid'])
        base.assert_no_error(self.client.groups.remove_user, group['uuid'], user2['uuid'])  # Twice

        result = self.client.groups.get_users(group['uuid'])
        assert_that(result, has_entries('items', contains_inanyorder(user1)))

    @fixtures.http_user_register()
    @fixtures.http_user_register()
    @fixtures.http_group()
    def test_put(self, group, user1, user2):
        base.assert_http_error(404, self.client.groups.add_user, base.UNKNOWN_UUID, user1['uuid'])
        base.assert_http_error(404, self.client.groups.add_user, group['uuid'], base.UNKNOWN_UUID)
        base.assert_no_error(self.client.groups.add_user, group['uuid'], user1['uuid'])
        base.assert_no_error(self.client.groups.add_user, group['uuid'], user1['uuid'])  # Twice

        result = self.client.groups.get_users(group['uuid'])
        assert_that(result, has_entries('items', contains_inanyorder(user1)))

    @fixtures.http_group(name='ignored')
    @fixtures.http_group(name='baz')
    @fixtures.http_group(name='bar')
    @fixtures.http_group(name='foo')
    @fixtures.http_user_register()
    def test_group_list(self, user, foo, bar, baz, ignored):
        for group in (foo, bar, baz):
            self.client.groups.add_user(group['uuid'], user['uuid'])

        result = self.client.users.get_groups(user['uuid'])
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains_inanyorder(
                has_entries('name', 'foo'),
                has_entries('name', 'bar'),
                has_entries('name', 'baz'))))

        result = self.client.users.get_groups(user['uuid'], search='ba')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 2,
            'items', contains_inanyorder(
                has_entries('name', 'bar'),
                has_entries('name', 'baz'))))

        result = self.client.users.get_groups(user['uuid'], name='foo')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 1,
            'items', contains_inanyorder(
                has_entries('name', 'foo'))))

        result = self.client.users.get_groups(user['uuid'], order='name', direction='desc')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('name', 'foo'),
                has_entries('name', 'baz'),
                has_entries('name', 'bar'))))

        result = self.client.users.get_groups(user['uuid'], order='name', direction='desc', offset=1)
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('name', 'baz'),
                has_entries('name', 'bar'))))

        result = self.client.users.get_groups(user['uuid'], order='name', direction='desc', limit=2)
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('name', 'foo'),
                has_entries('name', 'baz'))))

    @fixtures.http_user_register(username='ignored')
    @fixtures.http_user_register(username='baz')
    @fixtures.http_user_register(username='bar')
    @fixtures.http_user_register(username='foo')
    @fixtures.http_group()
    def test_user_list(self, group, foo, bar, baz, ignored):
        for user in (foo, bar, baz):
            self.client.groups.add_user(group['uuid'], user['uuid'])

        result = self.client.groups.get_users(group['uuid'])
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains_inanyorder(
                has_entries('username', 'foo'),
                has_entries('username', 'bar'),
                has_entries('username', 'baz'))))

        result = self.client.groups.get_users(group['uuid'], search='ba')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 2,
            'items', contains_inanyorder(
                has_entries('username', 'bar'),
                has_entries('username', 'baz'))))

        result = self.client.groups.get_users(group['uuid'], username='foo')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 1,
            'items', contains_inanyorder(
                has_entries('username', 'foo'))))

        result = self.client.groups.get_users(group['uuid'], order='username', direction='desc')
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('username', 'foo'),
                has_entries('username', 'baz'),
                has_entries('username', 'bar'))))

        result = self.client.groups.get_users(group['uuid'], order='username', direction='desc', offset=1)
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('username', 'baz'),
                has_entries('username', 'bar'))))

        result = self.client.groups.get_users(group['uuid'], order='username', direction='desc', limit=2)
        assert_that(result, has_entries(
            'total', 3,
            'filtered', 3,
            'items', contains(
                has_entries('username', 'foo'),
                has_entries('username', 'baz'))))

    @fixtures.http_user_register(username='foo', password='bar')
    @fixtures.http_group(name='two')
    @fixtures.http_group(name='one')
    @fixtures.http_policy(name='main', acl_templates=[
        '{% for group in groups %}\nmain.{{ group.name }}.*\n{% endfor %}',
        '{% for group in groups %}\nmain.{{ group.uuid }}\n{% endfor %}',
    ])
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
