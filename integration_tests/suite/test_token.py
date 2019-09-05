# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import assert_that, ends_with, has_entries

from .helpers.base import WazoAuthTestCase


class TestTokens(WazoAuthTestCase):

    def test_that_a_token_has_a_remote_address_and_user_agent(self):
        ua = 'My Test Runner'

        post_result = self.client.token.new(expiration=1, user_agent=ua)
        assert_that(post_result, has_entries(user_agent=ua, remote_addr=ends_with('.1')))
        # Docker host address are always X.X.X.1

        get_result = self.client.token.get(post_result['token'])
        assert_that(get_result, has_entries(user_agent=ua, remote_addr=ends_with('.1')))
