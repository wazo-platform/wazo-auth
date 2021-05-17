# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from hamcrest import assert_that, equal_to
from mock import Mock

from ..helpers import LocalTokenRenewer


class TestLocalTokenRenewer(unittest.TestCase):
    def setUp(self):
        self.token_service = Mock()
        self.acl = ['access.1', 'access.2.#']

        self.token_renewer = LocalTokenRenewer(self.token_service, acl=self.acl)

    def test_get_token_first_token(self):
        token = self.token_renewer.get_token()

        self.token_service.new_token_internal.assert_called_once_with(
            expiration=3600,
            acl=self.acl,
        )
        assert_that(
            token,
            equal_to(self.token_service.new_token_internal.return_value.token),
        )

    def test_that_a_new_token_is_not_created_at_each_call(self):
        token_1 = self.token_renewer.get_token()
        token_2 = self.token_renewer.get_token()

        assert_that(token_1, equal_to(token_2))

    def test_that_revoke_token_does_nothing_when_no_token(self):
        self.token_renewer.revoke_token()

        assert_that(self.token_service.remove_token.called, equal_to(False))

    def test_that_revoke_revokes_the_token(self):
        token = self.token_renewer.get_token()

        self.token_renewer.revoke_token()

        self.token_service.remove_token.assert_called_once_with(token)
