# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import os
import time
import requests

from hamcrest import assert_that, calling, has_properties, equal_to
from xivo_test_helpers.hamcrest.raises import raises
from xivo_auth_client import Client
from xivo_test_helpers.asset_launching_test_case import AssetLaunchingTestCase

HOST = os.getenv('WAZO_AUTH_TEST_HOST', 'localhost')


class BaseTestCase(AssetLaunchingTestCase):

    assets_root = os.path.join(os.path.dirname(__file__), '../..', 'assets')
    service = 'auth'

    @classmethod
    def setUpClass(cls):
        super(BaseTestCase, cls).setUpClass()

    def get_host(self):
        return HOST

    def _post_token(self, username, password, backend=None, expiration=None):
        port = self.service_port(9497, 'auth')
        client = Client(self.get_host(), port, username=username, password=password, verify_certificate=False)
        backend = backend or 'mock'
        args = {}
        if expiration:
            args['expiration'] = expiration
        return client.token.new(backend, **args)

    def _post_token_with_expected_exception(self, username, password, backend=None, expiration=None,
                                            status_code=None, msg=None):
        try:
            self._post_token(username, password, backend, expiration)
        except requests.HTTPError as e:
            if status_code:
                assert_that(e.response.status_code, equal_to(status_code))
            if msg:
                assert_that(e.response.json()['reason'][0], equal_to(msg))
        else:
            self.fail('Should have raised an exception')

    def _get_token(self, token, acls=None):
        port = self.service_port(9497, 'auth')
        client = Client(self.get_host(), port, verify_certificate=False)
        args = {}
        if acls:
            args['required_acl'] = acls
        return client.token.get(token, **args)

    def _get_token_with_expected_exception(self, token, acls=None, status_code=None, msg=None):
        try:
            self._get_token(token, acls)
        except requests.HTTPError as e:
            if status_code:
                assert_that(e.response.status_code, equal_to(status_code))
            if msg:
                assert_that(e.response.json()['reason'][0], equal_to(msg))
        else:
            self.fail('Should have raised an exception')

    def _delete_token(self, token):
        port = self.service_port(9497, 'auth')
        client = Client(self.get_host(), port, verify_certificate=False)
        return client.token.revoke(token)

    def _is_valid(self, token, acls=None):
        port = self.service_port(9497, 'auth')
        client = Client(self.get_host(), port, verify_certificate=False)
        args = {}
        if acls:
            args['required_acl'] = acls
        return client.token.is_valid(token, **args)

    def _assert_that_wazo_auth_is_stopping(self):
        for _ in range(5):
            if not self.service_status('auth')['State']['Running']:
                break
            time.sleep(0.2)
        else:
            self.fail('wazo-auth did not stop')


class MockBackendTestCase(BaseTestCase):

    asset = 'mock_backend'

    def setUp(self):
        super(MockBackendTestCase, self).setUp()
        port = self.service_port(9497, 'auth')
        self.client = Client(self.get_host(), port, username='foo', password='bar', verify_certificate=False)
        token = self.client.token.new(backend='mock', expiration=3600)['token']
        self.client.set_token(token)


def assert_no_error(fn, *args, **kwargs):
    return fn(*args, **kwargs)


def assert_http_error(status_code, fn, *args, **kwargs):
    assert_that(
        calling(fn).with_args(*args, **kwargs),
        raises(requests.HTTPError).matching(
            has_properties('response', has_properties('status_code', status_code))))
