# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest import TestCase
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse
from uuid import UUID

import requests
from flask import Flask
from flask_restful import Api
from hamcrest import (
    assert_that,
    calling,
    contains_exactly,
    contains_string,
    equal_to,
    has_entries,
    has_entry,
    has_key,
    not_,
    raises,
    starts_with,
)

from wazo_auth.exceptions import (
    ExternalAuthAlreadyExists,
    ExternalAuthConfigNotFound,
    UnknownUserException,
)

from ..plugin import SalesforcePlugin
from .helpers import (
    ACCESS_TOKEN,
    CLIENT_ID,
    CLIENT_SECRET,
    CODE,
    CONFIG,
    INSTANCE_URL,
    NEW_ACCESS_TOKEN,
    REFRESH_TOKEN,
    TOKEN_URL,
    FakeTokenEndpoint,
    salesforce_token_body,
)

USER_UUID = '7a7d3c4e-4b1f-4bd4-8f5e-8b2a7c6d0001'
TENANT_UUID = '7a7d3c4e-4b1f-4bd4-8f5e-8b2a7c6d0002'
URL = f'/0.1/users/{USER_UUID}/external/salesforce'
NOW = 1_800_000_000
MODULE = 'wazo_auth.plugins.external_auth.salesforce.http'


class SalesforceResourceTestCase(TestCase):
    def setUp(self):
        self.external_auth_service = Mock()
        self.external_auth_service.get_config.return_value = {
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
        }
        self.user_service = Mock()
        app = Flask('wazo-auth')
        app.config['token_service'] = Mock()
        app.config['user_service'] = self.user_service
        api = Api(app, prefix='/0.1')
        SalesforcePlugin().load(
            {
                'api': api,
                'config': CONFIG,
                'external_auth_service': self.external_auth_service,
                'user_service': self.user_service,
            }
        )
        self.client = app.test_client()

        patches = {
            'Tenant': patch(f'{MODULE}.Tenant'),
            'RelayListener': patch(f'{MODULE}.RelayListener'),
            'commit_or_rollback': patch(f'{MODULE}.commit_or_rollback'),
            'time': patch(f'{MODULE}.time'),
        }
        self.mocks = {name: p.start() for name, p in patches.items()}
        for p in patches.values():
            self.addCleanup(p.stop)
        self.mocks['Tenant'].autodetect.return_value = Mock(uuid=TENANT_UUID)
        self.mocks['time'].time.return_value = NOW

    def post(self, body):
        return self.client.post(URL, json=body, headers={'X-Auth-Token': 'x'})

    def get(self):
        return self.client.get(URL, headers={'X-Auth-Token': 'x'})

    def stored(self, **link):
        self.external_auth_service.get.return_value = link


class TestPost(SalesforceResourceTestCase):
    def test_answers_the_authorization_url_and_its_state(self):
        response = self.post({})

        assert_that(response.status_code, equal_to(201))
        url = urlparse(response.json['authorization_url'])
        query = parse_qs(url.query)
        assert_that(
            response.json['authorization_url'],
            starts_with(CONFIG['salesforce']['authorization_base_url']),
        )
        assert_that(
            query,
            has_entries(
                client_id=[CLIENT_ID],
                redirect_uri=[CONFIG['salesforce']['redirect_uri']],
                state=[response.json['state']],
                scope=['api refresh_token'],
                response_type=['code'],
            ),
        )
        self.external_auth_service.get_config.assert_called_once_with(
            'salesforce', TENANT_UUID
        )

    def test_the_body_scope_replaces_the_configured_one(self):
        response = self.post({'scope': ['api', 'id']})

        query = parse_qs(urlparse(response.json['authorization_url']).query)
        assert_that(query, has_entry('scope', ['api id']))

    def test_waits_for_the_code_on_the_relay_of_its_state(self):
        response = self.post({})

        RelayListener = self.mocks['RelayListener']
        RelayListener.assert_called_once()
        args = RelayListener.call_args
        assert_that(
            args.args[:2],
            contains_exactly('wss://oauth.example.com', response.json['state']),
        )
        RelayListener.return_value.start.assert_called_once_with()

    def test_invalid_bodies_answer_400(self):
        for body in (
            {'scope': 'api'},
            {'scope': [42]},
            {'scope': ['']},
            {'scope': ['a' * 513]},
        ):
            response = self.post(body)

            assert_that(response.status_code, equal_to(400), body)
            assert_that(response.json, has_entry('error_id', 'invalid-data'), body)
        self.mocks['RelayListener'].assert_not_called()

    def test_no_tenant_config_answers_404(self):
        self.external_auth_service.get_config.side_effect = ExternalAuthConfigNotFound(
            'salesforce'
        )

        response = self.post({})

        assert_that(response.status_code, equal_to(404))
        self.mocks['RelayListener'].assert_not_called()

    def test_unknown_user_is_refused_before_the_relay(self):
        self.user_service.get_user.side_effect = UnknownUserException(USER_UUID)

        response = self.post({})

        assert_that(response.status_code, equal_to(404))
        self.mocks['RelayListener'].assert_not_called()


class TestLinkCompletion(SalesforceResourceTestCase):
    def deliver_code(self, endpoint):
        self.post({})
        on_code = self.mocks['RelayListener'].call_args.args[2]
        with endpoint.serving():
            on_code(CODE)

    def test_stores_the_link_from_the_token_response(self):
        endpoint = FakeTokenEndpoint((200, salesforce_token_body()))

        self.deliver_code(endpoint)

        self.external_auth_service.create.assert_called_once_with(
            UUID(USER_UUID),
            'salesforce',
            {
                'access_token': ACCESS_TOKEN,
                'refresh_token': REFRESH_TOKEN,
                'token_expiration': NOW + 7200,
                'scope': 'api refresh_token id',
                'instance_url': INSTANCE_URL,
            },
        )
        self.mocks['commit_or_rollback'].assert_called_once_with()
        request = endpoint.requests[0]
        assert_that(request.url, equal_to(TOKEN_URL))
        body = parse_qs(request.body)
        assert_that(
            body,
            has_entries(
                grant_type=['authorization_code'],
                code=[CODE],
                client_id=[CLIENT_ID],
                client_secret=[CLIENT_SECRET],
            ),
        )

    def test_an_existing_link_is_replaced(self):
        self.external_auth_service.create.side_effect = ExternalAuthAlreadyExists(
            'salesforce'
        )
        endpoint = FakeTokenEndpoint((200, salesforce_token_body()))

        self.deliver_code(endpoint)

        self.external_auth_service.update.assert_called_once()
        assert_that(
            self.external_auth_service.update.call_args.args[2],
            has_entries(access_token=ACCESS_TOKEN, instance_url=INSTANCE_URL),
        )

    def test_a_refused_code_stores_nothing_and_does_not_raise(self):
        endpoint = FakeTokenEndpoint((400, {'error': 'invalid_grant'}))

        self.deliver_code(endpoint)

        self.external_auth_service.create.assert_not_called()
        self.external_auth_service.update.assert_not_called()
        self.mocks['commit_or_rollback'].assert_called_once_with()

    def test_a_malformed_expires_in_stores_nothing(self):
        endpoint = FakeTokenEndpoint((200, salesforce_token_body(expires_in='soon')))

        self.deliver_code(endpoint)

        self.external_auth_service.create.assert_not_called()

    def test_an_unreachable_token_endpoint_stores_nothing(self):
        endpoint = FakeTokenEndpoint(requests.ConnectionError('refused'))

        self.deliver_code(endpoint)

        self.external_auth_service.create.assert_not_called()


class TestGet(SalesforceResourceTestCase):
    def test_a_fresh_token_is_returned_as_stored(self):
        self.stored(
            access_token=ACCESS_TOKEN,
            refresh_token=REFRESH_TOKEN,
            token_expiration=NOW + 3600,
            scope='api refresh_token id',
            instance_url=INSTANCE_URL,
        )

        response = self.get()

        assert_that(response.status_code, equal_to(200))
        assert_that(
            response.json,
            equal_to(
                {
                    'access_token': ACCESS_TOKEN,
                    'token_expiration': NOW + 3600,
                    'scope': 'api refresh_token id',
                    'instance_url': INSTANCE_URL,
                }
            ),
        )
        self.external_auth_service.update.assert_not_called()

    def test_a_link_of_the_previous_package_reads_with_a_null_instance_url(self):
        self.stored(
            access_token=ACCESS_TOKEN,
            refresh_token=REFRESH_TOKEN,
            token_expiration=float(NOW + 3600),
        )

        response = self.get()

        assert_that(response.status_code, equal_to(200))
        assert_that(
            response.json,
            has_entries(
                access_token=ACCESS_TOKEN,
                token_expiration=NOW + 3600,
                scope=None,
                instance_url=None,
            ),
        )
        assert_that(response.json, not_(has_key('refresh_token')))

    def test_an_expired_token_is_refreshed_keeping_the_stored_refresh_token(self):
        self.stored(
            access_token=ACCESS_TOKEN,
            refresh_token=REFRESH_TOKEN,
            token_expiration=NOW - 1,
            scope='api refresh_token id',
            instance_url='https://old.my.salesforce.com',
        )
        endpoint = FakeTokenEndpoint(
            (
                200,
                salesforce_token_body(
                    access_token=NEW_ACCESS_TOKEN, refresh_token=None, scope=None
                ),
            )
        )

        with endpoint.serving():
            response = self.get()

        assert_that(response.status_code, equal_to(200))
        assert_that(
            response.json,
            equal_to(
                {
                    'access_token': NEW_ACCESS_TOKEN,
                    'token_expiration': NOW + 7200,
                    'scope': 'api refresh_token id',
                    'instance_url': INSTANCE_URL,
                }
            ),
        )
        self.external_auth_service.update.assert_called_once_with(
            UUID(USER_UUID),
            'salesforce',
            {
                'access_token': NEW_ACCESS_TOKEN,
                'refresh_token': REFRESH_TOKEN,
                'token_expiration': NOW + 7200,
                'scope': 'api refresh_token id',
                'instance_url': INSTANCE_URL,
            },
        )
        body = parse_qs(endpoint.requests[0].body)
        assert_that(
            body,
            has_entries(
                grant_type=['refresh_token'],
                refresh_token=[REFRESH_TOKEN],
                client_id=[CLIENT_ID],
                client_secret=[CLIENT_SECRET],
            ),
        )

    def test_an_expired_token_without_refresh_token_answers_link_expired(self):
        self.stored(access_token=ACCESS_TOKEN, token_expiration=NOW - 1)

        response = self.get()

        assert_that(response.status_code, equal_to(404))
        assert_that(response.json, has_entry('error_id', 'salesforce-link-expired'))
        assert_that(
            response.get_data(as_text=True), not_(contains_string(ACCESS_TOKEN))
        )
        self.external_auth_service.update.assert_not_called()

    def test_a_refused_refresh_answers_502_without_the_token(self):
        self.stored(
            access_token=ACCESS_TOKEN,
            refresh_token=REFRESH_TOKEN,
            token_expiration=NOW - 1,
        )
        endpoint = FakeTokenEndpoint(
            (400, {'error': 'invalid_grant', 'error_description': 'expired'})
        )

        with endpoint.serving():
            response = self.get()

        self.assert_refresh_failed(response)

    def test_an_unreachable_token_endpoint_answers_502(self):
        self.stored(
            access_token=ACCESS_TOKEN,
            refresh_token=REFRESH_TOKEN,
            token_expiration=NOW - 1,
        )
        endpoint = FakeTokenEndpoint(requests.ConnectionError('refused'))

        with endpoint.serving():
            response = self.get()

        self.assert_refresh_failed(response)

    def test_a_token_endpoint_answering_html_answers_502(self):
        self.stored(
            access_token=ACCESS_TOKEN,
            refresh_token=REFRESH_TOKEN,
            token_expiration=NOW - 1,
        )
        endpoint = FakeTokenEndpoint(
            (503, '<html><body>Down: maintenance</body></html>')
        )

        with endpoint.serving():
            response = self.get()

        self.assert_refresh_failed(response)

    def test_a_malformed_expires_in_answers_502(self):
        self.stored(
            access_token=ACCESS_TOKEN,
            refresh_token=REFRESH_TOKEN,
            token_expiration=NOW - 1,
        )
        body = salesforce_token_body(access_token=NEW_ACCESS_TOKEN, expires_in='soon')
        endpoint = FakeTokenEndpoint((200, body))

        with endpoint.serving():
            response = self.get()

        self.assert_refresh_failed(response)

    def test_no_tenant_config_on_refresh_answers_404(self):
        self.stored(
            access_token=ACCESS_TOKEN,
            refresh_token=REFRESH_TOKEN,
            token_expiration=NOW - 1,
        )
        self.external_auth_service.get_config.side_effect = ExternalAuthConfigNotFound(
            'salesforce'
        )

        response = self.get()

        assert_that(response.status_code, equal_to(404))
        assert_that(
            response.get_data(as_text=True), not_(contains_string(ACCESS_TOKEN))
        )

    def assert_refresh_failed(self, response):
        assert_that(response.status_code, equal_to(502))
        assert_that(response.json, has_entry('error_id', 'salesforce-refresh-failed'))
        assert_that(
            response.get_data(as_text=True), not_(contains_string(ACCESS_TOKEN))
        )
        self.external_auth_service.update.assert_not_called()


class TestDelete(SalesforceResourceTestCase):
    def test_removes_the_link(self):
        response = self.client.delete(URL, headers={'X-Auth-Token': 'x'})

        assert_that(response.status_code, equal_to(204))
        self.external_auth_service.delete.assert_called_once_with(
            UUID(USER_UUID), 'salesforce'
        )


class TestFakeTokenEndpoint(TestCase):
    def test_raises_what_it_is_given(self):
        endpoint = FakeTokenEndpoint(requests.ConnectionError('x'))
        with endpoint.serving():
            assert_that(
                calling(requests.get).with_args(TOKEN_URL),
                raises(requests.ConnectionError),
            )
