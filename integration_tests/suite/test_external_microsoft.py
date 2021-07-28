# Copyright 2019-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time
import requests

from hamcrest import (
    assert_that,
    empty,
    calling,
    has_entries,
    has_key,
    none,
    not_,
)

from wazo_auth_client import Client
from xivo_test_helpers import until
from xivo_test_helpers.hamcrest.raises import raises

from .helpers import base
from .helpers.base import BaseTestCase as _BaseTestCase

MICROSOFT = 'microsoft'
AUTHORIZE_URL = 'http://127.0.0.1:{port}/microsoft/authorize/{state}'


class BaseTestCase(_BaseTestCase):

    username = 'mario'
    password = 'mario'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        port = cls.service_port(9497, 'auth')
        cls.client = Client(
            '127.0.0.1',
            port=port,
            prefix=None,
            https=False,
            username=cls.username,
            password=cls.password,
        )
        token_data = cls.client.token.new(backend='wazo_user', expiration=7200)
        cls.admin_user_uuid = token_data['metadata']['uuid']
        cls.client.set_token(token_data['token'])

        cls.top_tenant_uuid = cls.get_top_tenant()['uuid']

    @classmethod
    def get_top_tenant(cls):
        return cls.client.tenants.list(name='master')['items'][0]


class TestAuthMicrosoft(BaseTestCase):

    asset = 'auth_microsoft'

    @classmethod
    def setUpClass(self):
        super().setUpClass()
        config = {'client_id': 'a-client-id', 'client_secret': 'a-client-secret'}
        self.client.external.create_config(MICROSOFT, config, self.top_tenant_uuid)

    @classmethod
    def tearDownClass(self):
        try:
            self.client.external.delete_config(MICROSOFT, self.top_tenant_uuid)
        except requests.HTTPError:
            pass
        super().tearDownClass()

    def tearDown(self):
        try:
            self.client.external.delete(MICROSOFT, self.admin_user_uuid)
        except requests.HTTPError:
            pass

    def test_when_create_authorize_get_then_does_not_raise(self):
        result = self.client.external.create(MICROSOFT, self.admin_user_uuid, {})

        self._simulate_user_authentication(result['state'])

        assert_that(
            calling(self.client.external.get).with_args(
                MICROSOFT, self.admin_user_uuid
            ),
            not_(raises(requests.HTTPError)),
        )

    def test_when_create_twice_with_authorize_then_does_not_raise(self):
        result = self.client.external.create(MICROSOFT, self.admin_user_uuid, {})
        self._simulate_user_authentication(result['state'])
        old_result = self.client.external.get(MICROSOFT, self.admin_user_uuid)
        result = self.client.external.create(MICROSOFT, self.admin_user_uuid, {})
        self._simulate_user_authentication(result['state'])

        def _token_is_updated():
            try:
                result = self.client.external.get(MICROSOFT, self.admin_user_uuid)
            except requests.HTTPError:
                return False
            return result['token_expiration'] != old_result['token_expiration']

        until.true(_token_is_updated, timeout=15, interval=1)

    def test_when_get_then_token_returned(self):
        result = self.client.external.create(MICROSOFT, self.admin_user_uuid, {})
        self._simulate_user_authentication(result['state'])

        response = self.client.external.get(MICROSOFT, self.admin_user_uuid)

        assert_that(
            response,
            has_entries(
                access_token=not_(none()),
                token_expiration=not_(none()),
                scope=not_(empty()),
            ),
        )

    def test_given_no_external_auth_confirmed_when_get_then_not_found(self):
        result = self.client.external.create(MICROSOFT, self.admin_user_uuid, {})

        base.assert_http_error(
            404, self.client.external.get, MICROSOFT, self.admin_user_uuid
        )
        self._simulate_user_authentication(result['state'])
        self.client.external.get(MICROSOFT, self.admin_user_uuid)

    def test_given_no_external_auth_when_delete_then_not_found(self):
        base.assert_http_error(
            404, self.client.external.delete, MICROSOFT, self.admin_user_uuid
        )

    def test_given_no_external_auth_when_get_then_not_found(self):
        base.assert_http_error(
            404, self.client.external.get, MICROSOFT, self.admin_user_uuid
        )

    def test_when_create_then_url_returned(self):
        response = self.client.external.create(MICROSOFT, self.admin_user_uuid, {})

        assert_that(response, has_key('authorization_url'))

    def test_when_create_twice_without_authorize_then_not_created(self):
        self.client.external.create(MICROSOFT, self.admin_user_uuid, {})

        assert_that(
            calling(self.client.external.create).with_args(
                MICROSOFT, self.admin_user_uuid, {}
            ),
            not_(raises(requests.HTTPError)),
        )

    def test_when_delete_then_not_found(self):
        base.assert_http_error(
            404, self.client.external.delete, MICROSOFT, self.admin_user_uuid
        )

    def test_when_delete_nothing_then_not_found(self):
        base.assert_http_error(
            404, self.client.external.delete, MICROSOFT, self.admin_user_uuid
        )

    def _simulate_user_authentication(self, state):
        authorize_url = AUTHORIZE_URL.format(
            port=self.service_port(80, 'oauth2sync'), state=state
        )
        response = requests.get(authorize_url)
        response.raise_for_status()

        def _is_microsoft_token_fetched():
            try:
                return self.client.external.get(MICROSOFT, self.admin_user_uuid)
            except requests.HTTPError:
                return False

        # if the external auth-data already existed from a previous test we might get a false
        # positive in _is_microsoft_token_fetched
        time.sleep(1.0)
        response = until.true(_is_microsoft_token_fetched, timeout=15, interval=1)
        assert_that(response, not_(False), 'failed to simulate user authentication')


class TestAuthMicrosoftWithNoConfig(BaseTestCase):

    asset = 'auth_microsoft'

    def test_given_no_config_when_create_then_not_found(self):
        base.assert_http_error(
            404, self.client.external.create, MICROSOFT, self.admin_user_uuid, {}
        )
