# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import (
    assert_that,
    ends_with,
    equal_to,
    has_entries,
    has_key,
    not_,
)

from .helpers.base import WazoAuthTestCase


class TestTokens(WazoAuthTestCase):

    def test_that_a_token_has_a_remote_address_and_user_agent(self):
        ua = 'My Test Runner'

        post_result = self.client.token.new(expiration=1, user_agent=ua)
        assert_that(post_result, has_entries(user_agent=ua, remote_addr=ends_with('.1')))
        # Docker host address are always X.X.X.1

        get_result = self.client.token.get(post_result['token'])
        assert_that(get_result, has_entries(user_agent=ua, remote_addr=ends_with('.1')))

    def test_refresh_token(self):
        client_id = 'my-test'

        result = self.client.token.new(expiration=1, access_type='offline', client_id=client_id)
        assert_that(result, has_entries(refresh_token=not_(None)))

        refresh_token = result['refresh_token']

        result = self.client.token.new(
            expiration=1,
            refresh_token=refresh_token,
            client_id=client_id,
        )
        assert_that(result, not_(has_key('refresh_token')))

    def test_that_only_one_refresh_token_exist_for_each_user_uuid_client_id(self):
        client_id = 'two-refresh-token'

        result_1 = self.client.token.new(expiration=1, access_type='offline', client_id=client_id)
        result_2 = self.client.token.new(expiration=1, access_type='offline', client_id=client_id)

        assert_that(result_1['refresh_token'], equal_to(result_2['refresh_token']))
