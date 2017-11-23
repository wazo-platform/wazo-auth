# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    has_entries,
)
from .helpers import base, fixtures


class TestGroupPolicyAssociation(base.MockBackendTestCase):

    @fixtures.http_policy()
    @fixtures.http_policy()
    @fixtures.http_group()
    def test_delete(self, group, policy1, policy2):
        self.client.groups.add_policy(group['uuid'], policy1['uuid'])
        self.client.groups.add_policy(group['uuid'], policy2['uuid'])

        base.assert_http_error(404, self.client.groups.remove_policy, base.UNKNOWN_UUID, policy1['uuid'])
        base.assert_http_error(404, self.client.groups.remove_policy, group['uuid'], base.UNKNOWN_UUID)
        base.assert_no_error(self.client.groups.remove_policy, group['uuid'], policy2['uuid'])
        base.assert_http_error(404, self.client.groups.remove_policy, group['uuid'], policy2['uuid'])  # Twice

        result = self.client.groups.get_policies(group['uuid'])
        assert_that(result, has_entries('items', contains(policy1)))

    @fixtures.http_policy()
    @fixtures.http_policy()
    @fixtures.http_group()
    def test_put(self, group, policy1, policy2):
        base.assert_http_error(404, self.client.groups.add_policy, base.UNKNOWN_UUID, policy1['uuid'])
        base.assert_http_error(404, self.client.groups.add_policy, group['uuid'], base.UNKNOWN_UUID)
        base.assert_no_error(self.client.groups.add_policy, group['uuid'], policy1['uuid'])
        base.assert_no_error(self.client.groups.add_policy, group['uuid'], policy1['uuid'])  # Twice

        result = self.client.groups.get_policies(group['uuid'])
        assert_that(result, has_entries('items', contains(policy1)))

    @fixtures.http_policy(name='ignored')
    @fixtures.http_policy(name='baz')
    @fixtures.http_policy(name='bar')
    @fixtures.http_policy(name='foo')
    @fixtures.http_group()
    def test_list_policies(self, group, foo, bar, baz, ignored):
        for policy in (foo, bar, baz):
            self.client.groups.add_policy(group['uuid'], policy['uuid'])

        def assert_list_result(result, filtered, match_fn, *names):
            assert_that(result, has_entries(
                'total', 3,
                'filtered', filtered,
                'items', match_fn(
                    *[has_entries('name', name) for name in names])))

        assert_list_result(
            self.client.groups.get_policies(group['uuid']),
            3, contains_inanyorder, 'foo', 'bar', 'baz')

        assert_list_result(
            self.client.groups.get_policies(group['uuid'], search='ba'),
            2, contains_inanyorder, 'bar', 'baz')

        assert_list_result(
            self.client.groups.get_policies(group['uuid'], name='foo'),
            1, contains, 'foo')

        assert_list_result(
            self.client.groups.get_policies(group['uuid'], order='name', direction='desc'),
            3, contains, 'foo', 'baz', 'bar')

        assert_list_result(
            self.client.groups.get_policies(group['uuid'], order='name', direction='desc', offset=1),
            3, contains, 'baz', 'bar')

        assert_list_result(
            self.client.groups.get_policies(group['uuid'], order='name', direction='desc', limit=2),
            3, contains, 'foo', 'baz')
