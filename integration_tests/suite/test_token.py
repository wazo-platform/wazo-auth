# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest

from mock import ANY
from hamcrest import (
    assert_that,
    calling,
    contains,
    contains_inanyorder,
    ends_with,
    equal_to,
    has_entries,
    has_key,
    has_properties,
    not_,
)
from requests.exceptions import HTTPError
from xivo_test_helpers.hamcrest.raises import raises

from .helpers import fixtures
from .helpers.base import WazoAuthTestCase, assert_http_error
from .helpers.constants import UNKNOWN_UUID


class TestTokens(WazoAuthTestCase):
    @fixtures.http.user(username='foo', password='bar')
    @fixtures.http.token(
        username='foo', password='bar', client_id='foobar',
        access_type='offline', session_type='mobile',
    )
    @fixtures.http.token(
        username='foo', password='bar', client_id='foobaz', access_type='offline'
    )
    def test_that_a_token_has_a_mobile_field(self, _, __, user):
        result = self.client.token.list(user_uuid=user['uuid'])

        assert_that(result, has_entries(items=contains_inanyorder(
            has_entries(client_id='foobar', mobile=True),
            has_entries(client_id='foobaz', mobile=False),
        )))

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
    def test_refresh_token_delete(self, token, user):
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
    @fixtures.http.token(username='foo', password='bar', access_type='offline')
    @fixtures.http.token(username='foo', password='bar', access_type='offline')
    @fixtures.http.token(
        username='foo', password='bar',
        access_type='offline', client_id='foobaz', session_type='mobile',
    )
    def test_refresh_token_list(self, token_1, token_2, token_3, user):
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
                items=contains_inanyorder(has_entries(client_id=token_1['client_id'])),
                filtered=1,
                total=3,
            ),
        )

        result = self.client.token.list(user_uuid=user['uuid'], mobile=True)
        assert_that(
            result,
            has_entries(
                items=contains_inanyorder(has_entries(client_id=token_1['client_id'])),
                filtered=1,
                total=3,
            ),
        )

        result = self.client.token.list(
            user_uuid=user['uuid'], order='created_at', direction='asc'
        )
        assert_that(
            result,
            has_entries(
                items=contains(
                    has_entries(client_id=token_3['client_id']),
                    has_entries(client_id=token_2['client_id']),
                    has_entries(client_id=token_1['client_id']),
                )
            ),
        )

        result = self.client.token.list(
            user_uuid=user['uuid'], order='created_at', direction='desc'
        )
        assert_that(
            result,
            has_entries(
                items=contains(
                    has_entries(client_id=token_1['client_id']),
                    has_entries(client_id=token_2['client_id']),
                    has_entries(client_id=token_3['client_id']),
                )
            ),
        )

        result = self.client.token.list(
            user_uuid=user['uuid'], order='created_at', limit=2
        )
        assert_that(
            result,
            has_entries(
                items=contains(
                    has_entries(client_id=token_3['client_id']),
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
                items=contains(
                    has_entries(client_id=token_2['client_id']),
                    has_entries(client_id=token_1['client_id']),
                )
            ),
        )

    @fixtures.http.user(username='foo', password='bar')
    @fixtures.http.token(username='foo', password='bar', access_type='offline')
    @fixtures.http.token(username='foo', password='bar', access_type='offline')
    @fixtures.http.token(
        username='foo', password='bar', access_type='offline', client_id='foobaz'
    )
    def test_refresh_token_list_from_user(self, token_1, token_2, token_3, user):
        client = self.new_auth_client('foo', 'bar')
        assert_http_error(401, client.token.list, user_uuid='me')

        client.set_token(token_1['token'])
        result = client.token.list(user_uuid='me')
        expected = self.client.token.list(user_uuid=user['uuid'])

        assert_that(result, equal_to(expected))

    @fixtures.http.user(username='foo', password='bar')
    @fixtures.http.token(
        username='foo', password='bar', client_id='foobar', access_type='offline'
    )
    def test_refresh_token_delete_from_user(self, token, user):
        client = self.new_auth_client('foo', 'bar')
        assert_http_error(401, client.token.delete, 'me', 'foobar')

        client.set_token(token['token'])
        client.token.delete('me', 'foobar')

        assert_http_error(404, client.token.delete, 'me', 'foobar')
