# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time
from urllib.parse import parse_qs, urlparse

import requests
import yaml
from hamcrest import (
    assert_that,
    close_to,
    contains_inanyorder,
    contains_string,
    equal_to,
    has_entries,
    has_entry,
    has_item,
    not_,
    starts_with,
)
from wazo_test_helpers import until

from .helpers import base

SALESFORCE = 'salesforce'
AUTHORIZE_URL = 'http://127.0.0.1:{port}/salesforce/authorize/{state}'
APP = {'client_id': 'a-client-id', 'client_secret': 'a-client-secret'}


def _user_route(test):
    return (
        f'http://127.0.0.1:{test.auth_port()}/0.1/users/'
        f'{test.admin_user_uuid}/external/salesforce'
    )


@base.use_asset('base')
class TestSalesforceOffByDefault(base.APIIntegrationTest):
    def test_the_user_route_is_not_loaded(self):
        response = requests.get(
            _user_route(self), headers={'X-Auth-Token': self.admin_token}
        )

        assert_that(response.status_code, equal_to(404))
        # a loaded plugin answers its own error_id; an absent route has none
        assert_that(response.text, not_(contains_string('error_id')))

    def test_salesforce_is_not_an_external_auth_type(self):
        result = self.client.external.list_(self.admin_user_uuid)

        assert_that(result['items'], not_(has_item(has_entries(type=SALESFORCE))))
        assert_that(result['items'], has_item(has_entries(type='microsoft')))


class SalesforceIntegrationTest(base.APIIntegrationTest):
    asset_cls = base.SalesforceAssetLaunchingTestCase


@base.use_asset('salesforce')
class TestAuthSalesforce(SalesforceIntegrationTest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.client.external.create_config(SALESFORCE, APP, cls.top_tenant_uuid)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.client.external.delete_config(SALESFORCE, cls.top_tenant_uuid)
        except requests.HTTPError:
            pass
        super().tearDownClass()

    def tearDown(self):
        try:
            self.client.external.delete(SALESFORCE, self.admin_user_uuid)
        except requests.HTTPError:
            pass

    def test_post_answers_an_authorization_url_for_the_tenant_app(self):
        result = self.client.external.create(SALESFORCE, self.admin_user_uuid, {})

        url = result['authorization_url']
        assert_that(
            url, starts_with('https://login.salesforce.com/services/oauth2/authorize?')
        )
        assert_that(
            parse_qs(urlparse(url).query),
            has_entries(
                client_id=['a-client-id'],
                redirect_uri=['http://oauth2sync:80/salesforce/authorize'],
                state=[result['state']],
                response_type=['code'],
                scope=['api refresh_token'],
            ),
        )
        self._simulate_user_authentication(result['state'])

    def test_get_after_the_relay_returns_the_salesforce_token(self):
        result = self.client.external.create(
            SALESFORCE, self.admin_user_uuid, {'scope': ['api']}
        )
        self._simulate_user_authentication(result['state'])

        response = self.client.external.get(SALESFORCE, self.admin_user_uuid)

        assert_that(
            response,
            has_entries(
                access_token=starts_with('access_token-'),
                scope='api refresh_token id',
                instance_url='https://example.my.salesforce.com',
                token_expiration=close_to(time.time() + 7200, 10),
            ),
        )

    def test_responses_match_the_api_spec(self):
        api = yaml.safe_load(
            requests.get(f'http://127.0.0.1:{self.auth_port()}/0.1/api/api.yml').text
        )
        definitions = api['definitions']
        operations = api['paths']['/users/{user_uuid}/external/salesforce']
        assert_that(set(operations), equal_to({'get', 'post', 'delete'}))

        posted = self.client.external.create(SALESFORCE, self.admin_user_uuid, {})
        self._simulate_user_authentication(posted['state'])
        got = self.client.external.get(SALESFORCE, self.admin_user_uuid)

        assert_that(
            list(posted),
            contains_inanyorder(*definitions['SalesforcePostResult']['properties']),
        )
        assert_that(
            list(got),
            contains_inanyorder(*definitions['SalesforceGetResult']['properties']),
        )

    def test_salesforce_is_an_external_auth_type_once_enabled(self):
        result = self.client.external.list_(self.admin_user_uuid)

        assert_that(result['items'], has_item(has_entries(type=SALESFORCE)))

    def test_without_a_link_get_answers_the_plugin_404(self):
        response = requests.get(
            _user_route(self), headers={'X-Auth-Token': self.admin_token}
        )

        assert_that(response.status_code, equal_to(404))
        assert_that(response.json(), has_entry('error_id', 'unknown-external-auth'))

    def test_invalid_body_answers_400(self):
        for body in ({'scope': 'api'}, {'scope': ['']}, {'scope': ['a' * 513]}):
            base.assert_http_error(
                400, self.client.external.create, SALESFORCE, self.admin_user_uuid, body
            )

    def test_delete_removes_the_link(self):
        result = self.client.external.create(SALESFORCE, self.admin_user_uuid, {})
        self._simulate_user_authentication(result['state'])

        self.client.external.delete(SALESFORCE, self.admin_user_uuid)

        base.assert_http_error(
            404, self.client.external.get, SALESFORCE, self.admin_user_uuid
        )

    def _simulate_user_authentication(self, state):
        authorize_url = AUTHORIZE_URL.format(port=self.oauth2_port(), state=state)

        def _relay_listens():
            return requests.get(authorize_url).status_code == 204

        until.true(_relay_listens, timeout=15, interval=0.5)

        def _link_stored():
            try:
                return self.client.external.get(SALESFORCE, self.admin_user_uuid)
            except requests.HTTPError:
                return False

        until.true(_link_stored, timeout=15, interval=0.5)


@base.use_asset('salesforce')
class TestAuthSalesforceWithNoConfig(SalesforceIntegrationTest):
    def test_given_no_config_when_create_then_not_found(self):
        base.assert_http_error(
            404, self.client.external.create, SALESFORCE, self.admin_user_uuid, {}
        )
