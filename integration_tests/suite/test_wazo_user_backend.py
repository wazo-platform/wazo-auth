# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import (
    assert_that,
    has_entries,
    has_items,
)
from .helpers import fixtures
from .helpers.base import (
    assert_http_error,
    MockBackendTestCase,
)
from xivo_test_helpers.hamcrest.uuid_ import uuid_


class TestWazoUserBackend(MockBackendTestCase):

    @fixtures.http_user_register(username='foobar', email_address='foobar@example.com', password='s3cr37')
    def test_token_creation(self, user):
        response = self._post_token(user['username'], 's3cr37', backend='wazo_user')
        assert_that(
            response,
            has_entries(
                'token', uuid_(),
                'auth_id', user['uuid'],
                'acls', has_items(
                    'confd.#',
                    'plugind.#')))

        assert_http_error(401, self._post_token, user['username'], 'not-our-password', backend='wazo_user')
        assert_http_error(401, self._post_token, 'not-foobar', 's3cr37', backend='wazo_user')

    def test_no_password(self):
        user = self.client.users.new(username='foobar', email_address='foobar@example.com')
        try:
            assert_http_error(401, self._post_token, user['username'], 'p45sw0rd', backend='wazo_user')
        finally:
            self.client.users.delete(user['uuid'])
