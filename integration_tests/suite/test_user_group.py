# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import (
    assert_that,
    contains_inanyorder,
    has_entries,
)
from .helpers import base, fixtures


class TestUserGroupAssociation(base.MockBackendTestCase):

    @fixtures.http_user()
    @fixtures.http_user()
    @fixtures.http_group()
    def test_delete(self, group, user1, user2):
        self.client.groups.add_user(group['uuid'], user1['uuid'])
        self.client.groups.add_user(group['uuid'], user2['uuid'])

        base.assert_http_error(404, self.client.groups.remove_user, base.UNKNOWN_UUID, user1['uuid'])
        base.assert_http_error(404, self.client.groups.remove_user, group['uuid'], base.UNKNOWN_UUID)
        base.assert_no_error(self.client.groups.remove_user, group['uuid'], user2['uuid'])
        base.assert_http_error(404, self.client.groups.remove_user, group['uuid'], user2['uuid'])  # Twice

        result = self.client.groups.get_users(group['uuid'])
        assert_that(result, has_entries('items', contains_inanyorder(user1)))

    @fixtures.http_user()
    @fixtures.http_user()
    @fixtures.http_group()
    def test_put(self, group, user1, user2):
        base.assert_http_error(404, self.client.groups.add_user, base.UNKNOWN_UUID, user1['uuid'])
        base.assert_http_error(404, self.client.groups.add_user, group['uuid'], base.UNKNOWN_UUID)
        base.assert_no_error(self.client.groups.add_user, group['uuid'], user1['uuid'])
        base.assert_no_error(self.client.groups.add_user, group['uuid'], user1['uuid'])  # Twice

        result = self.client.groups.get_users(group['uuid'])
        assert_that(result, has_entries('items', contains_inanyorder(user1)))
