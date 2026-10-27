# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import hashlib
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
    has_length,
    not_,
    raises,
    starts_with,
)

from wazo_auth.exceptions import (
    ExternalAuthAlreadyExists,
    ExternalAuthConfigNotFound,
    UnknownExternalAuthException,
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
OTHER_TENANT_UUID = '7a7d3c4e-4b1f-4bd4-8f5e-8b2a7c6d0004'
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
        # Mock refuses attributes named assert_*, unless set
        self.user_service.assert_user_in_subtenant = Mock()
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
        self.user_service.assert_user_in_subtenant.side_effect = UnknownUserException(
            USER_UUID
        )

        response = self.post({})

        assert_that(response.status_code, equal_to(404))
        self.user_service.assert_user_in_subtenant.assert_called_once_with(
            TENANT_UUID, UUID(USER_UUID)
        )
        self.mocks['RelayListener'].assert_not_called()

    def test_asks_salesforce_for_a_pkce_challenge(self):
        response = self.post({})

        query = parse_qs(urlparse(response.json['authorization_url']).query)
        assert_that(query, has_entry('code_challenge_method', ['S256']))
        assert_that(query['code_challenge'][0], has_length(43))


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
                'app_tenant_uuid': TENANT_UUID,
            },
        )
        self.mocks['commit_or_rollback'].assert_called_once_with()
        assert_that(endpoint.timeouts, equal_to([10]))
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

    def test_the_code_exchange_proves_the_pkce_challenge(self):
        response = self.post({})
        on_code = self.mocks['RelayListener'].call_args.args[2]
        endpoint = FakeTokenEndpoint((200, salesforce_token_body()))
        with endpoint.serving():
            on_code(CODE)

        query = parse_qs(urlparse(response.json['authorization_url']).query)
        verifier = parse_qs(endpoint.requests[0].body)['code_verifier'][0]
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).decode().rstrip('=')
        assert_that(query['code_challenge'], equal_to([challenge]))

    def test_a_link_that_cannot_be_stored_is_logged_and_does_not_raise(self):
        self.external_auth_service.create.side_effect = UnknownUserException(USER_UUID)
        endpoint = FakeTokenEndpoint((200, salesforce_token_body()))

        with self.assertLogs(MODULE, level='ERROR') as logs:
            self.deliver_code(endpoint)

        assert_that(logs.output[0], contains_string(USER_UUID))
        assert_that(logs.output[0], contains_string(TENANT_UUID))
        assert_that(logs.output[0], contains_string('UnknownUserException'))
        self.mocks['commit_or_rollback'].assert_called_once_with()

    def test_each_callback_stores_for_its_own_user_whatever_the_order(self):
        other_user = '7a7d3c4e-4b1f-4bd4-8f5e-8b2a7c6d0003'
        self.post({})
        self.client.post(
            f'/0.1/users/{other_user}/external/salesforce',
            json={},
            headers={'X-Auth-Token': 'x'},
        )
        first, second = (c.args[2] for c in self.mocks['RelayListener'].call_args_list)
        endpoint = FakeTokenEndpoint(
            (200, salesforce_token_body(access_token='second-token')),
            (200, salesforce_token_body(access_token='first-token')),
        )

        with endpoint.serving():
            second('second-code')
            first('first-code')

        stored = {
            str(c.args[0]): c.args[2]['access_token']
            for c in self.external_auth_service.create.call_args_list
        }
        assert_that(
            stored, equal_to({other_user: 'second-token', USER_UUID: 'first-token'})
        )
        codes = [parse_qs(r.body)['code'] for r in endpoint.requests]
        assert_that(codes, contains_exactly(['second-code'], ['first-code']))

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
        assert_that(endpoint.timeouts, equal_to([10]))
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

    def test_the_refresh_uses_the_app_that_issued_the_link(self):
        self.stored(
            access_token=ACCESS_TOKEN,
            refresh_token=REFRESH_TOKEN,
            token_expiration=NOW - 1,
            app_tenant_uuid=OTHER_TENANT_UUID,
        )
        refresh = (200, salesforce_token_body(access_token=NEW_ACCESS_TOKEN))

        with FakeTokenEndpoint(refresh).serving():
            response = self.get()

        assert_that(response.status_code, equal_to(200))
        assert_that(response.json, not_(has_key('app_tenant_uuid')))
        self.external_auth_service.get_config.assert_called_once_with(
            'salesforce', OTHER_TENANT_UUID
        )

    def test_a_link_without_its_app_tenant_refreshes_with_the_callers(self):
        self.stored(
            access_token=ACCESS_TOKEN,
            refresh_token=REFRESH_TOKEN,
            token_expiration=NOW - 1,
        )
        refresh = (200, salesforce_token_body(access_token=NEW_ACCESS_TOKEN))

        with FakeTokenEndpoint(refresh).serving():
            self.get()

        self.external_auth_service.get_config.assert_called_once_with(
            'salesforce', TENANT_UUID
        )

    def test_expires_in_sent_as_text_on_refresh(self):
        self.stored(
            access_token=ACCESS_TOKEN,
            refresh_token=REFRESH_TOKEN,
            token_expiration=NOW - 1,
        )
        body = salesforce_token_body(access_token=NEW_ACCESS_TOKEN, expires_in='3600')

        with FakeTokenEndpoint((200, body)).serving():
            response = self.get()

        assert_that(response.status_code, equal_to(200))
        assert_that(response.json, has_entry('token_expiration', NOW + 3600))

    def test_a_link_replaced_during_the_refresh_still_answers_the_new_token(self):
        for error in (
            UnknownExternalAuthException('salesforce'),
            ExternalAuthAlreadyExists('salesforce'),
        ):
            self.stored(
                access_token=ACCESS_TOKEN,
                refresh_token=REFRESH_TOKEN,
                token_expiration=NOW - 1,
            )
            self.external_auth_service.update.side_effect = error
            refresh = (200, salesforce_token_body(access_token=NEW_ACCESS_TOKEN))

            with FakeTokenEndpoint(refresh).serving():
                response = self.get()

            assert_that(response.status_code, equal_to(200), error)
            assert_that(
                response.json, has_entry('access_token', NEW_ACCESS_TOKEN), error
            )

    def test_a_user_outside_the_callers_tenants_is_refused(self):
        self.user_service.assert_user_in_subtenant.side_effect = UnknownUserException(
            USER_UUID
        )

        response = self.get()

        assert_that(response.status_code, equal_to(404))
        self.user_service.assert_user_in_subtenant.assert_called_once_with(
            TENANT_UUID, UUID(USER_UUID)
        )
        self.external_auth_service.get.assert_not_called()

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

    def test_a_user_outside_the_callers_tenants_is_refused(self):
        self.user_service.assert_user_in_subtenant.side_effect = UnknownUserException(
            USER_UUID
        )

        response = self.client.delete(URL, headers={'X-Auth-Token': 'x'})

        assert_that(response.status_code, equal_to(404))
        self.user_service.assert_user_in_subtenant.assert_called_once_with(
            TENANT_UUID, UUID(USER_UUID)
        )
        self.external_auth_service.delete.assert_not_called()


class TestFakeTokenEndpoint(TestCase):
    def test_raises_what_it_is_given(self):
        endpoint = FakeTokenEndpoint(requests.ConnectionError('x'))
        with endpoint.serving():
            assert_that(
                calling(requests.get).with_args(TOKEN_URL),
                raises(requests.ConnectionError),
            )
