# Copyright 2019-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time

import requests
from hamcrest import assert_that, calling, empty, has_entries, has_key, none, not_
from wazo_test_helpers import until
from wazo_test_helpers.hamcrest.raises import raises

from .helpers import base

GOOGLE = 'google'
AUTHORIZE_URL = 'http://127.0.0.1:{port}/google/authorize/{state}'


@base.use_asset('base')
class TestAuthGoogle(base.APIIntegrationTest):
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

        base.assert_http_error(
            404, self.client.external.get, GOOGLE, self.admin_user_uuid
        )
        self._simulate_user_authentication(result['state'])
        self.client.external.get(GOOGLE, self.admin_user_uuid)

    def test_given_no_external_auth_when_delete_then_not_found(self):
        base.assert_http_error(
            404, self.client.external.delete, GOOGLE, self.admin_user_uuid
        )

    def test_given_no_external_auth_when_get_then_not_found(self):
        base.assert_http_error(
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
        base.assert_http_error(
            404, self.client.external.delete, GOOGLE, self.admin_user_uuid
        )

    def test_when_delete_nothing_then_not_found(self):
        base.assert_http_error(
            404, self.client.external.delete, GOOGLE, self.admin_user_uuid
        )

    def _simulate_user_authentication(self, state):
        authorize_url = AUTHORIZE_URL.format(port=self.oauth2_port(), state=state)
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


@base.use_asset('base')
class TestAuthGoogleWithNoConfig(base.APIIntegrationTest):
    def test_given_no_config_when_create_then_not_found(self):
        base.assert_http_error(
            404, self.client.external.create, GOOGLE, self.admin_user_uuid, {}
        )
