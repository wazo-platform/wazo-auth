# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest import TestCase

from hamcrest import assert_that, contains
from mock import sentinel as s, Mock

from ..authentication import AuthenticationService


class TestAuthenticationService(TestCase):
    def setUp(self):
        self.dao = Mock()
        self.backend = Mock()
        self.backends = {s.backend_name: Mock(obj=self.backend)}

        self.service = AuthenticationService(self.dao, self.backends)

    def test_verify_auth_refresh_token(self):
        args = {'refresh_token': s.refresh_token, 'client_id': s.client_id}
        self.dao.refresh_token.get.return_value = {
            'login': s.original_login,
            'backend_name': s.backend_name,
        }

        result = self.service.verify_auth(args)

        assert_that(result, contains(self.backend, s.original_login))

    def test_verify_auth_with_login_password(self):
        args = {'backend': s.backend_name, 'login': s.login, 'password': s.password}

        self.backend.verify_password.return_value = True
        result = self.service.verify_auth(args)

        assert_that(result, contains(self.backend, s.login))
