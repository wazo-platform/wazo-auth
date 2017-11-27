# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from uuid import uuid4
from hamcrest import (assert_that, equal_to)
from .helpers import base, fixtures


class TestExternalAuthAPI(base.MockBackendTestCase):

    asset = 'external_auth'
    original_data = {'secret': str(uuid4())}

    @fixtures.http_user_register()
    def test_create(self, user):
        result = self.client.external.create('foo', user['uuid'], self.original_data)
        assert_that(result, equal_to(self.original_data))

        data = self.client.external.get('foo', user['uuid'])
        assert_that(data, equal_to(self.original_data))

        base.assert_http_error(404, self.client.external.create, 'notfoo', user['uuid'], self.original_data)
        base.assert_http_error(404, self.client.external.create, 'foo', base.UNKNOWN_UUID, self.original_data)

    @fixtures.http_user_register()
    def test_delete(self, user):
        self.client.external.create('foo', user['uuid'], self.original_data)

        base.assert_http_error(404, self.client.external.delete, 'notfoo', user['uuid'])
        base.assert_http_error(404, self.client.external.delete, 'foo', base.UNKNOWN_UUID)
        base.assert_no_error(self.client.external.delete, 'foo', user['uuid'])
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
