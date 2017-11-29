# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import os
import time
import requests

from hamcrest import assert_that, calling, has_properties, equal_to
from xivo_test_helpers.hamcrest.raises import raises
from xivo_auth_client import Client
from xivo_test_helpers.asset_launching_test_case import AssetLaunchingTestCase

HOST = os.getenv('WAZO_AUTH_TEST_HOST', 'localhost')
UNKNOWN_UUID = '00000000-0000-0000-0000-000000000000'


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
        self._auth_port = self.service_port(9497, 'auth')
        self.client = self.new_auth_client('foo', 'bar')
        token = self.client.token.new(backend='mock', expiration=3600)['token']
        self.client.set_token(token)

    def new_auth_client(self, username, password):
        host = self.get_host()
        port = self._auth_port
        return Client(host, port=port, username=username, password=password, verify_certificate=False)


def assert_no_error(fn, *args, **kwargs):
    return fn(*args, **kwargs)


def assert_http_error(status_code, fn, *args, **kwargs):
    assert_that(
        calling(fn).with_args(*args, **kwargs),
        raises(requests.HTTPError).matching(
            has_properties('response', has_properties('status_code', status_code))))
