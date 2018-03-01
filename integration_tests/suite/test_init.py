# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from xivo_test_helpers.mock import ANY_UUID
from hamcrest import (
    assert_that,
    has_entries,
    empty,
)
from .helpers.base import (
    assert_http_error,
    assert_no_error,
    MockBackendTestCase,
)

INVALID_KEY = '0' * 20


class TestInit(MockBackendTestCase):

    def setUp(self):
        super(TestInit, self).setUp()
        self.docker_exec(['wazo-auth-bootstrap'])
        self.key = self.docker_exec(['cat', '/var/lib/wazo-auth/init.key'])

    def test_post(self):
        body = {
            'username': 'foo',
            'password': 'bar',
            'key': INVALID_KEY,
        }
        assert_http_error(401, self.client.init.run, **body)
        assert_http_error(400, self.client.init.run, **copy_without(body, 'username'))
        assert_http_error(400, self.client.init.run, **copy_without(body, 'password'))
        assert_http_error(400, self.client.init.run, **copy_without(body, 'key'))

        result = self.client.init.run(username='foo', password='bar', key=self.key)
        assert_that(result, has_entries(uuid=ANY_UUID, emails=empty(), username='foo'))

        assert_no_error(self._post_token, 'foo', 'bar', backend='wazo_user', expiration=10)


def copy_without(body, key):
    copy = dict(body)
    copy.pop(key)
    return copy
