# Copyright 2017-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from hamcrest import assert_that, equal_to
from mock import Mock

from ..helpers import LocalTokenRenewer


class TestLocalTokenRenewer(unittest.TestCase):
    def setUp(self):
        self._token_service = Mock()
        self._backend = Mock()
        self._user_service = Mock()
        self._user_service.list_users.return_value = [Mock()]

        self.local_token_renewer = LocalTokenRenewer(
            self._backend, self._token_service, self._user_service
        )

    def test_get_token_first_token(self):
        token = self.local_token_renewer.get_token()

        self._token_service.new_token.assert_called_once_with(
            self._backend.obj,
            'wazo-auth',
            {
                'expiration': 3600,
                'backend': 'wazo_user',
                'user_agent': '',
                'remote_addr': '127.0.0.1',
            },
        )

        assert_that(token, equal_to(self._token_service.new_token.return_value.token))

    def test_that_a_new_token_is_not_created_at_each_call(self):
        token_1 = self.local_token_renewer.get_token()
        token_2 = self.local_token_renewer.get_token()

        assert_that(token_1, equal_to(token_2))

    def test_that_a_new_token_does_nothing_when_no_user(self):
        self._user_service.list_users.return_value = []
        token = self.local_token_renewer.get_token()

        assert_that(token, equal_to(None))

    def test_that_revoke_token_does_nothing_when_no_token(self):
        self.local_token_renewer.revoke_token()

        assert_that(self._token_service.remove_token.called, equal_to(False))

    def test_that_revoke_revokes_the_token(self):
        token = self.local_token_renewer.get_token()

        self.local_token_renewer.revoke_token()

        self._token_service.remove_token.assert_called_once_with(token)
