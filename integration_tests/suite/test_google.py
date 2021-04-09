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
    has_properties,
    has_property,
    none,
    not_,
)

from xivo_test_helpers import until
from xivo_test_helpers.hamcrest.raises import raises
from wazo_auth_client import Client

from wazo_auth import bootstrap
from wazo_auth.database import helpers

from .helpers.base import BaseTestCase


GOOGLE = 'google'
AUTHORIZE_URL = 'http://localhost:{port}/google/authorize/{state}'


class BaseGoogleTestCase(BaseTestCase):

    username = 'mario'
    password = 'mario'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        database = cls.new_db_client()
        until.true(database.is_up, timeout=5, message='Postgres did not come back up')
        bootstrap.create_initial_user(
            database.uri,
            cls.username,
            cls.password,
            bootstrap.PURPOSE,
            bootstrap.DEFAULT_POLICY_SLUG,
        )

        port = cls.service_port(9497, 'auth')
        cls.client = Client(
            'localhost',
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
    def tearDownClass(cls):
        helpers.deinit_db()
        super().tearDownClass()

    @classmethod
    def get_top_tenant(cls):
        return cls.client.tenants.list(name='master')['items'][0]


class TestAuthGoogle(BaseGoogleTestCase):

    asset = 'auth_google'

    @classmethod
    def setUpClass(self):
        super().setUpClass()
        config = {'client_id': 'a-client-id', 'client_secret': 'a-client-secret'}
        self.client.external.create_config(GOOGLE, config, self.top_tenant_uuid)

    @classmethod
    def tearDownClass(self):
        try:
            self.client.external.delete_config(GOOGLE, self.top_tenant_uuid)
        except requests.HTTPError:
            pass
        super().tearDownClass()

    def tearDown(self):
        try:
            self.client.external.delete(GOOGLE, self.admin_user_uuid)
        except requests.HTTPError:
            pass

    def test_when_create_authorize_get_then_does_not_raise(self):
        result = self.client.external.create(GOOGLE, self.admin_user_uuid, {})

        self._simulate_user_authentication(result['state'])

        assert_that(
            calling(self.client.external.get).with_args(GOOGLE, self.admin_user_uuid),
            not_(raises(requests.HTTPError)),
        )

    def test_when_create_twice_with_authorize_then_does_not_raise(self):
        result = self.client.external.create(GOOGLE, self.admin_user_uuid, {})
        self._simulate_user_authentication(result['state'])
        result = self.client.external.create(GOOGLE, self.admin_user_uuid, {})
        self._simulate_user_authentication(result['state'])

        assert_that(
            calling(self.client.external.get).with_args(GOOGLE, self.admin_user_uuid),
            not_(raises(requests.HTTPError)),
        )

    def test_when_get_then_token_returned(self):
        result = self.client.external.create(GOOGLE, self.admin_user_uuid, {})
        self._simulate_user_authentication(result['state'])

        response = self.client.external.get(GOOGLE, self.admin_user_uuid)

        assert_that(
            response,
            has_entries(
                access_token=not_(none()),
                token_expiration=not_(none()),
                scope=not_(empty()),
            ),
        )

    def test_given_no_external_auth_confirmed_when_get_then_not_found(self):
        result = self.client.external.create(GOOGLE, self.admin_user_uuid, {})

        _assert_that_raises_http_error(
            404, self.client.external.get, GOOGLE, self.admin_user_uuid
        )
        self._simulate_user_authentication(result['state'])
        self.client.external.get(GOOGLE, self.admin_user_uuid)

    def test_given_no_external_auth_when_delete_then_not_found(self):
        _assert_that_raises_http_error(
            404, self.client.external.delete, GOOGLE, self.admin_user_uuid
        )

    def test_given_no_external_auth_when_get_then_not_found(self):
        _assert_that_raises_http_error(
            404, self.client.external.get, GOOGLE, self.admin_user_uuid
        )

    def test_when_create_then_url_returned(self):
        response = self.client.external.create(GOOGLE, self.admin_user_uuid, {})

        assert_that(response, has_key('authorization_url'))

    def test_when_create_twice_without_authorize_then_not_created(self):
        self.client.external.create(GOOGLE, self.admin_user_uuid, {})

        assert_that(
            calling(self.client.external.create).with_args(
                GOOGLE, self.admin_user_uuid, {}
            ),
            not_(raises(requests.HTTPError)),
        )

    def test_when_delete_then_not_found(self):
        _assert_that_raises_http_error(
            404, self.client.external.delete, GOOGLE, self.admin_user_uuid
        )

    def test_when_delete_nothing_then_not_found(self):
        _assert_that_raises_http_error(
            404, self.client.external.delete, GOOGLE, self.admin_user_uuid
        )

    def _simulate_user_authentication(self, state):
        authorize_url = AUTHORIZE_URL.format(
            port=self.service_port(80, 'oauth2sync'), state=state
        )
        response = requests.get(authorize_url)
        response.raise_for_status()

        def _is_google_token_fetched():
            try:
                return self.client.external.get(GOOGLE, self.admin_user_uuid)
            except requests.HTTPError:
                return False

        # if the external auth-data already existed from a previous test we might get a false
        # positive in _is_google_token_fetched
        time.sleep(1.0)
        response = until.true(_is_google_token_fetched, timeout=15, interval=1)
        assert_that(response, not_(False), 'failed to simulate user authentication')


class TestAuthGoogleWithNoConfig(BaseGoogleTestCase):

    asset = 'auth_google'

    def test_given_no_config_when_create_then_not_found(self):
        _assert_that_raises_http_error(
            404, self.client.external.create, GOOGLE, self.admin_user_uuid, {}
        )


def _assert_that_raises_http_error(status_code, fn, *args, **kwargs):
    assert_that(
        calling(fn).with_args(*args, **kwargs),
        raises(requests.HTTPError).matching(
            has_property('response', has_properties('status_code', status_code))
        ),
    )
