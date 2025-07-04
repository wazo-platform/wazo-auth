# Copyright 2019-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from base64 import b64encode
from unittest.mock import ANY

import pytest
import requests
from hamcrest import (
    assert_that,
    calling,
    contains_exactly,
    contains_inanyorder,
    empty,
    ends_with,
    equal_to,
    has_entries,
    has_entry,
    has_key,
    has_properties,
    not_,
)
from requests.exceptions import HTTPError
from wazo_auth_client import Client
from wazo_test_helpers import until
from wazo_test_helpers.hamcrest.raises import raises

from .helpers import base, fixtures
from .helpers.base import assert_http_error
from .helpers.constants import MAXIMUM_CONCURRENT_USER_SESSIONS, UNKNOWN_UUID


@base.use_asset('base')
class TestTokens(base.APIIntegrationTest):
    @fixtures.http.user(username='large')
    def test_that_large_expiration_returns_a_400(self, user):
        client = Client(
            '127.0.0.1',
            port=self.auth_port(),
            prefix=None,
            https=False,
            username='large',
            password=user['password'],
        )
        try:
            client.token.new(expiration=9999999999999999999999)
        except HTTPError as e:
            assert e.response.status_code == 400

    @fixtures.http.user(email_address='u1@example.com')
    def test_that_the_email_can_be_used_to_get_a_token(self, u1):
        client = Client(
            '127.0.0.1',
            port=self.auth_port(),
            prefix=None,
            https=False,
            username='u1@example.com',
            password=u1['password'],
        )
        token_data = client.token.new(expiration=1)
        assert_that(token_data, has_entries(token=not_(None)))

    @fixtures.http.user(username=None, email_address='u1@example.com')
    @fixtures.http.user(username=None, email_address='u2@example.com')
    def test_that_the_email_can_be_used_to_get_a_token_when_many_users(self, u1, u2):
        client = Client('127.0.0.1', port=self.auth_port(), prefix=None, https=False)

        client.username = 'u1@example.com'
        client.password = u1['password']
        token_data = client.token.new(expiration=1)
        assert_that(token_data, has_entries(metadata=has_entries(uuid=u1['uuid'])))

        client.username = 'u2@example.com'
        client.password = u2['password']
        token_data = client.token.new(expiration=1)
        assert_that(token_data, has_entries(metadata=has_entries(uuid=u2['uuid'])))

    @fixtures.http.user(
        username=None, email_address='u1@example.com', password='pépéç€'
    )
    @fixtures.http.user(username=None, email_address='u2@example.com', password='pépéç')
    def test_unicode_password(self, u1, u2):
        client = Client('127.0.0.1', port=self.auth_port(), prefix=None, https=False)

        for username, password, charsets, uuid in [
            (
                'u1@example.com',
                'pépéç€',
                ['utf-8'],
                u1['uuid'],
            ),  # € is not included in the latin charset
            ('u2@example.com', 'pépéç', ['utf-8', 'latin'], u2['uuid']),
        ]:
            client.username = username
            client.password = password
            token_data = client.token.new(expiration=1)
            assert_that(token_data, has_entries(metadata=has_entries(uuid=uuid)))

            for charset in charsets:
                encoded_credentials = b64encode(
                    f'{client.username}:{client.password}'.encode(charset)
                )
                headers = {
                    'Authorization': b'Basic ' + encoded_credentials,
                    'Content-Type': 'application/json',
                }
                response = requests.post(
                    client.token.base_url, headers=headers, json={'expiration': 1}
                )
                assert_that(
                    response, has_properties(status_code=200), f'failed for {charset}'
                )

    @fixtures.http.user(username=None, email_address='u1@example.com')
    def test_username_is_logged_on_failed_attempts(self, u1):
        client = Client('127.0.0.1', port=self.auth_port(), prefix=None, https=False)

        client.username = 'u1@example.com'
        client.password = u1['password'][2:]  # invalid password

        with self.asset_cls.capture_logs(service_name='auth') as auth_logs:
            assert_http_error(401, client.token.new, expiration=1)

        assert re.search(
            r'INFO.*u1@example.com', auth_logs.result()
        ), 'username missing in logs'

    @fixtures.http.user(username=None, email_address='u1@example.com')
    def test_username_is_logged_on_successful_attempts(self, u1):
        client = Client('127.0.0.1', port=self.auth_port(), prefix=None, https=False)

        client.username = 'u1@example.com'
        client.password = u1['password']

        with self.asset_cls.capture_logs(service_name='auth') as auth_logs:
            token_data = client.token.new(expiration=1)

        token_id = 'XXXXXXXX-XXXX-XXXX-XXXX-XXXX' + token_data['token'][-8:]

        assert re.search(
            f'INFO.*u1@example.com.*{token_id}', auth_logs.result()
        ), 'username or token missing in logs'

    @fixtures.http.user(username='foo', password='bar')
    @fixtures.http.token(
        username='foo',
        password='bar',
        client_id='foobar',
        access_type='offline',
        session_type='mobile',
    )
    @fixtures.http.token(
        username='foo', password='bar', client_id='foobaz', access_type='offline'
    )
    def test_that_a_token_has_a_mobile_field(self, user, *_):
        result = self.client.token.list(user_uuid=user['uuid'])

        assert_that(
            result,
            has_entries(
                items=contains_inanyorder(
                    has_entries(client_id='foobar', mobile=True),
                    has_entries(client_id='foobaz', mobile=False),
                )
            ),
        )

    def test_that_a_token_has_a_remote_address_and_user_agent(self):
        ua = 'My Test Runner'

        post_result = self.client.token.new(expiration=10, user_agent=ua)
        assert_that(
            post_result, has_entries(user_agent=ua, remote_addr=ends_with('.1'))
        )
        # Docker host address are always X.X.X.1

        get_result = self.client.token.get(post_result['token'])
        assert_that(get_result, has_entries(user_agent=ua, remote_addr=ends_with('.1')))

    def test_refresh_token(self):
        client_id = 'my-test'

        result = self.client.token.new(
            expiration=1, access_type='offline', client_id=client_id
        )
        assert_that(result, has_entries(refresh_token=not_(None)))

        refresh_token = result['refresh_token']

        result = self.client.token.new(
            expiration=1, refresh_token=refresh_token, client_id=client_id
        )
        assert_that(result, not_(has_key('refresh_token')))

    @fixtures.http.user(username='foo')
    def test_refresh_token_created_event(self, user):
        msg_accumulator = self.bus.accumulator(
            headers={'name': 'auth_refresh_token_created'},
        )
        client_id = 'mytestapp'
        self._post_token(
            'foo',
            user['password'],
            session_type='Mobile',
            access_type='offline',
            client_id=client_id,
        )

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(with_headers=True),
                contains_exactly(
                    has_entries(
                        message=has_entries(
                            data={
                                'client_id': client_id,
                                'user_uuid': user['uuid'],
                                'tenant_uuid': user['tenant_uuid'],
                                'mobile': True,
                            }
                        ),
                        headers=has_entries(
                            name='auth_refresh_token_created',
                            tenant_uuid=user['tenant_uuid'],
                        ),
                    )
                ),
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)

    @fixtures.http.user(username='foo')
    def test_refresh_token_created_event_not_duplicated(self, user):
        client_id = 'mytestapp'
        self._post_token(
            'foo',
            user['password'],
            session_type='Mobile',
            access_type='offline',
            client_id=client_id,
        )

        msg_accumulator = self.bus.accumulator(
            headers={
                'name': 'auth_refresh_token_deleted',
            }
        )

        # The same same refresh token is returned, not a new one
        self._post_token(
            'foo',
            user['password'],
            session_type='Mobile',
            access_type='offline',
            client_id=client_id,
        )

        # The delete is to avoid waiting an arbitrary amount of time before considering that the
        # created event was not published
        self.client.token.delete(user['uuid'], client_id)

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(with_headers=True),
                contains_exactly(
                    has_entries(
                        message=has_entries(
                            data=has_entries(
                                client_id=client_id,
                                user_uuid=user['uuid'],
                                tenant_uuid=user['tenant_uuid'],
                            ),
                        ),
                        headers=has_entries(
                            name='auth_refresh_token_deleted',
                            tenant_uuid=user['tenant_uuid'],
                        ),
                    ),
                ),
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)

    def test_that_only_one_refresh_token_exist_for_each_user_uuid_client_id(self):
        client_id = 'two-refresh-token'

        result_1 = self.client.token.new(
            expiration=1, access_type='offline', client_id=client_id
        )
        result_2 = self.client.token.new(
            expiration=1, access_type='offline', client_id=client_id
        )

        assert_that(result_1['refresh_token'], equal_to(result_2['refresh_token']))

    def test_refresh_token_with_the_wrong_client_id(self):
        client_id = 'my-test'

        result = self.client.token.new(
            expiration=1, access_type='offline', client_id=client_id
        )
        assert_that(result, has_entries(refresh_token=not_(None)))

        refresh_token = result['refresh_token']

        assert_that(
            calling(self.client.token.new).with_args(
                expiration=1, refresh_token=refresh_token, client_id='another-client-id'
            ),
            raises(Exception).matching(
                has_properties(response=has_properties(status_code=401))
            ),
        )

    @fixtures.http.user(username='foo', password='bar')
    @fixtures.http.token(
        username='foo', password='bar', client_id='foobar', access_type='offline'
    )
    def test_refresh_token_delete(self, user, token):
        client_id = 'foobar'

        with pytest.raises(HTTPError) as excinfo:
            self.client.token.delete(UNKNOWN_UUID, client_id)

        assert_that(excinfo.value.response.status_code, equal_to(404))
        assert_that(
            excinfo.value.response.json(),
            has_entries(
                error_id='unknown-user',
                resource='users',
                details=has_entries(uuid=UNKNOWN_UUID),
            ),
        )

        assert_that(
            calling(self.client.token.delete).with_args(user['uuid'], client_id),
            not_(raises(Exception)),
        )

        with pytest.raises(HTTPError) as excinfo:
            self.client.token.delete(user['uuid'], client_id)

        assert_that(excinfo.value.response.status_code, equal_to(404))
        assert_that(
            excinfo.value.response.json(),
            has_entries(
                error_id='cannot-find-refresh-token-matching-client-id',
                resource='tokens',
                details=has_entries(client_id=client_id),
            ),
        )

    @fixtures.http.user(username='foo', password='bar')
    @fixtures.http.token(
        username='foo',
        password='bar',
        client_id='foobar',
        access_type='offline',
        session_type='mobile',
    )
    def test_refresh_token_deleted_event(self, user, token):
        client_id = 'foobar'
        msg_accumulator = self.bus.accumulator(
            headers={'name': 'auth_refresh_token_deleted'}
        )

        self.client.token.delete(user['uuid'], client_id)

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(with_headers=True),
                contains_exactly(
                    has_entries(
                        message=has_entries(
                            data={
                                'client_id': client_id,
                                'user_uuid': user['uuid'],
                                'tenant_uuid': user['tenant_uuid'],
                                'mobile': True,
                            }
                        ),
                        headers=has_entry('tenant_uuid', user['tenant_uuid']),
                    )
                ),
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)

    @fixtures.http.user(username='foo', password='bar')
    @fixtures.http.token(
        username='foo',
        password='bar',
        access_type='offline',
        client_id='client1',
    )
    @fixtures.http.token(
        username='foo',
        password='bar',
        access_type='offline',
        client_id='client2',
    )
    @fixtures.http.token(
        username='foo',
        password='bar',
        access_type='offline',
        client_id='foobaz',
        session_type='mobile',
    )
    def test_refresh_token_list(self, user, token_1, token_2, token_3):
        result = self.client.token.list(user_uuid=user['uuid'])
        assert_that(
            result,
            has_entries(
                total=3,
                filtered=3,
                items=contains_inanyorder(
                    has_entries(client_id=token_1['client_id'], created_at=ANY),
                    has_entries(client_id=token_2['client_id'], created_at=ANY),
                    has_entries(client_id=token_3['client_id'], created_at=ANY),
                ),
            ),
        )

        assert_http_error(404, self.client.token.list, UNKNOWN_UUID)
        assert_http_error(
            400, self.client.token.list, user['uuid'], limit='not a number'
        )
        assert_http_error(400, self.client.token.list, user['uuid'], offset=-1)
        assert_http_error(400, self.client.token.list, user['uuid'], direction='up')
        assert_http_error(400, self.client.token.list, user['uuid'], order='lol')

        result = self.client.token.list(user_uuid=user['uuid'], search='baz')
        assert_that(
            result,
            has_entries(
                items=contains_inanyorder(has_entries(client_id=token_3['client_id'])),
                filtered=1,
                total=3,
            ),
        )

        result = self.client.token.list(user_uuid=user['uuid'], mobile=True)
        assert_that(
            result,
            has_entries(
                items=contains_inanyorder(has_entries(client_id=token_3['client_id'])),
                filtered=1,
                total=3,
            ),
        )

        result = self.client.token.list(
            user_uuid=user['uuid'], order='mobile', direction='desc'
        )
        assert_that(result['items'][0], has_entries(client_id=token_3['client_id']))

        result = self.client.token.list(
            user_uuid=user['uuid'], order='created_at', direction='asc'
        )
        assert_that(
            result,
            has_entries(
                items=contains_exactly(
                    has_entries(client_id=token_1['client_id']),
                    has_entries(client_id=token_2['client_id']),
                    has_entries(client_id=token_3['client_id']),
                )
            ),
        )

        result = self.client.token.list(
            user_uuid=user['uuid'], order='created_at', direction='desc'
        )
        assert_that(
            result,
            has_entries(
                items=contains_exactly(
                    has_entries(client_id=token_3['client_id']),
                    has_entries(client_id=token_2['client_id']),
                    has_entries(client_id=token_1['client_id']),
                )
            ),
        )

        result = self.client.token.list(
            user_uuid=user['uuid'], order='created_at', limit=2
        )
        assert_that(
            result,
            has_entries(
                items=contains_exactly(
                    has_entries(client_id=token_1['client_id']),
                    has_entries(client_id=token_2['client_id']),
                )
            ),
        )

        result = self.client.token.list(
            user_uuid=user['uuid'], order='created_at', offset=1
        )
        assert_that(
            result,
            has_entries(
                items=contains_exactly(
                    has_entries(client_id=token_2['client_id']),
                    has_entries(client_id=token_3['client_id']),
                )
            ),
        )

    @fixtures.http.user(username='foo', password='bar')
    @fixtures.http.token(
        username='foo', password='bar', access_type='offline', client_id='foobaz'
    )
    @fixtures.http.token(username='foo', password='bar', access_type='offline')
    @fixtures.http.token(username='foo', password='bar', access_type='offline')
    def test_refresh_token_list_from_user(self, user, token_1, token_2, token_3):
        client = self.make_auth_client('foo', 'bar')
        assert_http_error(401, client.token.list, user_uuid='me')

        client.set_token(token_1['token'])
        result = client.token.list(user_uuid='me')
        expected = self.client.token.list(user_uuid=user['uuid'])

        assert_that(result, equal_to(expected))

    @fixtures.http.user(username='foo', password='bar')
    @fixtures.http.token(
        username='foo', password='bar', client_id='foobar', access_type='offline'
    )
    def test_refresh_token_delete_from_user(self, user, token):
        client = self.make_auth_client('foo', 'bar')
        assert_http_error(401, client.token.delete, 'me', 'foobar')

        client.set_token(token['token'])
        client.token.delete('me', 'foobar')

        assert_http_error(404, client.token.delete, 'me', 'foobar')

    @fixtures.http.tenant()
    @fixtures.http.user(username='foo', password='bar')
    @fixtures.http.token(
        username='foo', password='bar', access_type='offline', client_id='client1'
    )
    @fixtures.http.token(
        username='foo', password='bar', access_type='offline', client_id='client2'
    )
    @fixtures.http.token(
        username='foo',
        password='bar',
        access_type='offline',
        client_id='foobaz',
        session_type='Mobile',
    )
    def test_list_all_refresh_tokens(self, sub_tenant, user, token_1, token_2, token_3):
        result = self.client.refresh_tokens.list()

        assert_that(
            result,
            has_entries(
                items=contains_inanyorder(
                    has_entries(
                        client_id=token_1['client_id'],
                        user_uuid=user['uuid'],
                        tenant_uuid=user['tenant_uuid'],
                        metadata={},
                    ),
                    has_entries(
                        client_id=token_2['client_id'],
                        user_uuid=user['uuid'],
                        tenant_uuid=user['tenant_uuid'],
                        metadata={},
                    ),
                    has_entries(
                        client_id=token_3['client_id'],
                        user_uuid=user['uuid'],
                        tenant_uuid=user['tenant_uuid'],
                        metadata={},
                    ),
                ),
            ),
        )

        result = self.client.refresh_tokens.list(tenant_uuid=sub_tenant['uuid'])
        assert_that(result, has_entries(items=empty()))

        assert_http_error(400, self.client.refresh_tokens.list, limit='not a number')
        assert_http_error(400, self.client.refresh_tokens.list, offset=-1)
        assert_http_error(400, self.client.refresh_tokens.list, direction='up')
        assert_http_error(400, self.client.refresh_tokens.list, order='lol')

        result = self.client.refresh_tokens.list(search='baz')
        assert_that(
            result,
            has_entries(
                items=contains_inanyorder(has_entries(client_id=token_3['client_id'])),
                filtered=1,
                total=3,
            ),
        )

        result = self.client.refresh_tokens.list(mobile=True)
        assert_that(
            result,
            has_entries(
                items=contains_inanyorder(has_entries(client_id=token_3['client_id'])),
                filtered=1,
                total=3,
            ),
        )

        result = self.client.refresh_tokens.list(order='mobile', direction='desc')
        assert_that(result['items'][0], has_entries(client_id=token_3['client_id']))

        result = self.client.refresh_tokens.list(order='created_at', direction='asc')
        assert_that(
            result,
            has_entries(
                items=contains_exactly(
                    has_entries(client_id=token_1['client_id']),
                    has_entries(client_id=token_2['client_id']),
                    has_entries(client_id=token_3['client_id']),
                )
            ),
        )

        result = self.client.refresh_tokens.list(order='created_at', direction='desc')
        assert_that(
            result,
            has_entries(
                items=contains_exactly(
                    has_entries(client_id=token_3['client_id']),
                    has_entries(client_id=token_2['client_id']),
                    has_entries(client_id=token_1['client_id']),
                )
            ),
        )

        result = self.client.refresh_tokens.list(order='created_at', limit=2)
        assert_that(
            result,
            has_entries(
                items=contains_exactly(
                    has_entries(client_id=token_1['client_id']),
                    has_entries(client_id=token_2['client_id']),
                )
            ),
        )

        result = self.client.refresh_tokens.list(order='created_at', offset=1)
        assert_that(
            result,
            has_entries(
                items=contains_exactly(
                    has_entries(client_id=token_2['client_id']),
                    has_entries(client_id=token_3['client_id']),
                )
            ),
        )

    @fixtures.http.tenant(name='sub')
    def test_that_a_user_can_list_tokens_from_subtenants(self, sub):
        args = {
            'username': 'foobar',
            'firstname': 'Alice',
            'email_address': 'foobar@example.com',
            'password': 's3cr37',
            'tenant_uuid': sub['uuid'],
        }

        with self.user(self.client, **args) as user:
            client = self.make_auth_client('foobar', 's3cr37')
            client.token.new(expiration=1, client_id='myapp', access_type='offline')
            result = self.client.token.list(user['uuid'])
            assert_that(
                result,
                has_entries(
                    items=contains_exactly(
                        has_entries(
                            client_id='myapp',
                            user_uuid=user['uuid'],
                            tenant_uuid=sub['uuid'],
                        )
                    )
                ),
            )

    @fixtures.http.user(username='foo', purpose='user')
    def test_user_maximum_token_limit(self, user):
        client = self.make_auth_client('foo', user['password'])
        for _ in range(MAXIMUM_CONCURRENT_USER_SESSIONS):
            client.token.new(expiration=10, access_type='online')

        # Fails on 11th token
        assert_that(
            calling(client.token.new).with_args(expiration=10, access_type='online'),
            raises(HTTPError).matching(
                has_properties(response=has_properties(status_code=429))
            ),
        )

    @fixtures.http.user(username='my-service', purpose='external_api')
    def test_external_api_user_maximum_token_limit(self, user):
        client = self.make_auth_client('my-service', user['password'])
        for _ in range(MAXIMUM_CONCURRENT_USER_SESSIONS):
            client.token.new(expiration=10, access_type='online')

        assert_that(
            calling(client.token.new).with_args(expiration=10, access_type='online'),
            raises(HTTPError).matching(
                has_properties(response=has_properties(status_code=429))
            ),
        )

    @fixtures.http.user(username='foo', purpose='internal')
    def test_internal_user_should_not_have_token_limit(self, user):
        client = self.make_auth_client('foo', user['password'])
        for _ in range(MAXIMUM_CONCURRENT_USER_SESSIONS):
            client.token.new(expiration=10, access_type='online')

        assert_that(
            client.token.new(expiration=10, access_type='online'), has_key('token')
        )


@base.use_asset('metadata')
class TestTokensFromMetadata(base.MetadataIntegrationTest):
    # purpose internal enables the test metadata plugin
    @fixtures.http.user(username='foo', purpose='internal')
    def test_validating_internal_token(self, user):
        client = self.make_auth_client('foo', user['password'])
        token = client.token.new(expiration=10)
        assert token['metadata']['internal_token_is_valid'] is True

    @fixtures.http.user(username='foo', purpose='internal')
    def test_validating_refresh_token(self, user):
        client = self.make_auth_client('foo', user['password'])
        token = client.token.new(
            expiration=10,
            access_type='offline',
            client_id='my-test',
        )
        assert 'persistent' in token['metadata']
        persistent = token['metadata']['persistent']

        token = client.token.new(
            expiration=10,
            client_id='my-test',
            refresh_token=token['refresh_token'],
        )
        assert 'persistent' in token['metadata']
        assert token['metadata']['persistent'] == persistent

        refresh_token = self.client.refresh_tokens.list(client_id='my-test')
        assert refresh_token['items']
        assert 'persistent' in refresh_token['items'][0]['metadata']
        assert refresh_token['items'][0]['metadata']['persistent'] == persistent
