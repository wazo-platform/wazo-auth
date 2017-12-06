# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from uuid import uuid4
from hamcrest import (assert_that, contains, equal_to, has_entries)
from xivo_test_helpers import until
from .helpers import base, fixtures


class TestExternalAuthAPI(base.MockBackendTestCase):

    asset = 'external_auth'
    original_data = {'secret': str(uuid4())}

    @fixtures.http_user_register()
    def test_create(self, user):
        routing_key = 'auth.users.{}.external.foo.created'.format(user['uuid'])
        msg_accumulator = self.new_message_accumulator(routing_key)

        result = self.client.external.create('foo', user['uuid'], self.original_data)
        assert_that(result, equal_to(self.original_data))

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(),
                contains(has_entries(data=dict(user_uuid=user['uuid'], external_auth_name='foo'))))

        until.assert_(bus_received_msg, tries=10, interval=0.25)

        data = self.client.external.get('foo', user['uuid'])
        assert_that(data, equal_to(self.original_data))

        base.assert_http_error(404, self.client.external.create, 'notfoo', user['uuid'], self.original_data)
        base.assert_http_error(404, self.client.external.create, 'foo', base.UNKNOWN_UUID, self.original_data)

    @fixtures.http_user_register()
    def test_delete(self, user):
        routing_key = 'auth.users.{}.external.foo.deleted'.format(user['uuid'])
        msg_accumulator = self.new_message_accumulator(routing_key)

        self.client.external.create('foo', user['uuid'], self.original_data)

        base.assert_http_error(404, self.client.external.delete, 'notfoo', user['uuid'])
        base.assert_http_error(404, self.client.external.delete, 'foo', base.UNKNOWN_UUID)
        base.assert_no_error(self.client.external.delete, 'foo', user['uuid'])

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(),
                contains(has_entries(data=dict(user_uuid=user['uuid'], external_auth_name='foo'))))

        until.assert_(bus_received_msg, tries=10, interval=0.25)

        base.assert_http_error(404, self.client.external.get, 'foo', user['uuid'])

    @fixtures.http_user_register()
    @fixtures.http_user_register()
    def test_get(self, user1, user2):
        self.client.external.create('foo', user1['uuid'], self.original_data)

        base.assert_http_error(404, self.client.external.get, 'foo', user2['uuid'])
        base.assert_http_error(404, self.client.external.get, 'notfoo', user1['uuid'])

        assert_that(
            self.client.external.get('foo', user1['uuid']),
            equal_to(self.original_data))

    @fixtures.http_user_register()
    def test_update(self, user):
        new_data = {'foo': 'bar'}

        base.assert_http_error(404, self.client.external.update, 'foo', user['uuid'], new_data)
        self.client.external.create('foo', user['uuid'], self.original_data)
        base.assert_http_error(404, self.client.external.update, 'foo', base.UNKNOWN_UUID, new_data)
        base.assert_http_error(404, self.client.external.update, 'notfoo', user['uuid'], new_data)

        result = self.client.external.update('foo', user['uuid'], new_data)
        assert_that(result, equal_to(new_data))

        assert_that(self.client.external.get('foo', user['uuid']), equal_to(new_data))
