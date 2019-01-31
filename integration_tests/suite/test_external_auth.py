# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time
import requests
from uuid import uuid4
from hamcrest import (assert_that, contains, contains_inanyorder, equal_to, has_entries)
from xivo_test_helpers import until
from .helpers import base, fixtures


class TestExternalAuthAPI(base.WazoAuthTestCase):

    asset = 'external_auth'
    safe_data = {'scope': ['one', 'two', 'three']}
    original_data = dict(secret=str(uuid4()), **safe_data)

    @fixtures.http_user_register()
    def test_create(self, user):
        routing_key = 'auth.users.{}.external.foo.created'.format(user['uuid'])
        msg_accumulator = self.new_message_accumulator(routing_key)

        result = self.client.external.create('foo', user['uuid'], self.original_data)
        assert_that(result, has_entries(**self.original_data))

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(),
                contains(has_entries(data=dict(user_uuid=user['uuid'], external_auth_name='foo'))))

        until.assert_(bus_received_msg, tries=10, interval=0.25)

        data = self.client.external.get('foo', user['uuid'])
        assert_that(data, has_entries(**self.original_data))

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
            has_entries(**self.original_data))

    @fixtures.http_user_register()
    @fixtures.http_user_register()
    @fixtures.http_user_register()
    def test_list(self, user1, user2, user3):
        self.client.external.create('foo', user1['uuid'], self.original_data)
        self.client.external.create('bar', user1['uuid'], self.original_data)
        self.client.external.create('foo', user2['uuid'], self.original_data)

        result = self.client.external.list_(user3['uuid'])
        expected = [
            {'type': 'foo', 'data': {}, 'plugin_info': {}, 'enabled': False},
            {'type': 'bar', 'data': {}, 'plugin_info': {'foo': 'bar'}, 'enabled': False},
        ]
        assert_that(result, has_entries(items=contains_inanyorder(*expected), total=2, filtered=2))

        result = self.client.external.list_(user1['uuid'])
        expected = [
            {'type': 'foo', 'data': {}, 'plugin_info': {}, 'enabled': True},
            {'type': 'bar', 'data': self.safe_data, 'plugin_info': {'foo': 'bar'}, 'enabled': True},
        ]
        assert_that(result, has_entries(items=contains_inanyorder(*expected), total=2, filtered=2))

        result = self.client.external.list_(user1['uuid'], type='bar')
        expected = [
            {'type': 'bar', 'data': self.safe_data, 'plugin_info': {'foo': 'bar'}, 'enabled': True},
        ]
        assert_that(result, has_entries(items=contains(*expected), total=2, filtered=1))

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

    @fixtures.http_user()
    def test_external_oauth2(self, user):
        routing_key = 'auth.users.{}.external.foo.authorized'.format(user['uuid'])
        msg_accumulator = self.new_message_accumulator(routing_key)
        token = 'a-token'
        result = self.client.external.create('foo', user['uuid'], self.original_data)
        time.sleep(1)  # wazo-auth needs some time to connect its websocket
        self.authorize_oauth2('foo', result['state'], token)

        def oauth2_is_done():
            try:
                return self.client.external.get('foo', user['uuid'])
            except requests.HTTPError:
                return False

        data = until.true(oauth2_is_done, timeout=5, interval=0.25)

        assert_that(data, has_entries(access_token=token))

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(),
                contains(has_entries(data=dict(user_uuid=user['uuid'], external_auth_name='foo'))))

        until.assert_(bus_received_msg, tries=10, interval=0.25)

    def authorize_oauth2(self, auth_type, state, token):
        port = self.service_port(80, 'oauth2sync')
        url = 'http://localhost:{}/{}/authorize/{}'.format(port, auth_type, state)
        result = requests.get(url, params={'access_token': token})
        result.raise_for_status()
