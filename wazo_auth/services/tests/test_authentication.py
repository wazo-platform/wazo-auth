# Copyright 2019-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest import TestCase
from unittest.mock import Mock
from unittest.mock import sentinel as s

from hamcrest import assert_that, calling, contains_exactly, has_entries
from wazo_test_helpers.hamcrest.raises import raises

from wazo_auth import exceptions
from wazo_auth.services.saml import SAMLService
from wazo_auth.services.tenant import TenantService

from ..authentication import AuthenticationService


class TestAuthenticationService(TestCase):
    def setUp(self):
        self.dao = Mock()
        self.saml_service = Mock(SAMLService)
        self.tenant_service = Mock(TenantService)
        self.wazo_user_backend = Mock()
        self.ldap_user_backend = Mock()
        self.backends = {
            'wazo_user': Mock(obj=self.wazo_user_backend),
            'ldap_user': Mock(obj=self.ldap_user_backend),
        }

        self.service = AuthenticationService(
            self.dao,
            self.backends,
            self.tenant_service,
            self.saml_service,
        )

    def set_authorized_authentication_method(self, login, method):
        user = Mock(authentication_method=method)
        results = {login: user}
        self.dao.user.get_user_by_login.side_effect = results.get

    def test_verify_auth_refresh_token(self):
        self.set_authorized_authentication_method(s.original_login, 'native')
        args = {'refresh_token': s.refresh_token, 'client_id': s.client_id}
        self.dao.refresh_token.get.return_value = {
            'login': s.original_login,
            'backend_name': 'wazo_user',
        }

        result = self.service.verify_auth(args)

        assert_that(result, contains_exactly(self.wazo_user_backend, s.original_login))
        assert_that(args, has_entries(login=s.original_login))

    def test_verify_auth_refresh_token_user_deleted(self):
        self.dao.user.get_user_by_login.side_effect = exceptions.UnknownLoginException(
            s.original_login
        )
        args = {'refresh_token': s.refresh_token, 'client_id': s.client_id}
        self.dao.refresh_token.get.return_value = {
            'login': s.original_login,
            'backend_name': 'wazo_user',
        }

        assert_that(
            calling(self.service.verify_auth).with_args(args),
            raises(exceptions.UnknownLoginException),
        )

    def test_verify_auth_refresh_token_no_refresh_token(self):
        self.set_authorized_authentication_method(s.original_login, 'native')
        args = {'refresh_token': s.refresh_token, 'client_id': s.client_id}
        self.dao.refresh_token.get.side_effect = exceptions.UnknownRefreshToken(
            s.client_id
        )

        assert_that(
            calling(self.service.verify_auth).with_args(args),
            raises(exceptions.UnknownRefreshToken),
        )

    def test_verify_auth_with_login_password_native(self):
        self.set_authorized_authentication_method(s.login, 'native')
        args = {'login': s.login, 'password': s.password}

        self.wazo_user_backend.verify_password.return_value = True
        result = self.service.verify_auth(args)

        assert_that(result, contains_exactly(self.wazo_user_backend, s.login))

    def test_verify_auth_with_login_password_native_wrong_credentials(self):
        self.set_authorized_authentication_method(s.login, 'native')
        args = {'login': s.login, 'password': s.password}

        self.wazo_user_backend.verify_password.return_value = False
        assert_that(
            calling(self.service.verify_auth).with_args(args),
            raises(exceptions.InvalidUsernamePassword),
        )

    def test_verify_auth_with_login_password_ldap(self):
        self.set_authorized_authentication_method(s.login, 'ldap')
        args = {'login': s.login, 'password': s.password, 'domain_name': s.domain_name}

        def verify_password_mock(login, password, args):
            args['user_email'] = s.login
            return True

        self.ldap_user_backend.verify_password.side_effect = verify_password_mock
        result = self.service.verify_auth(args)

        assert_that(result, contains_exactly(self.ldap_user_backend, s.login))

    def test_verify_auth_with_login_password_ldap_wrong_credentials(self):
        self.set_authorized_authentication_method(s.login, 'ldap')
        args = {'login': s.login, 'password': s.password, 'domain_name': s.domain_name}

        self.ldap_user_backend.verify_password.return_value = False
        assert_that(
            calling(self.service.verify_auth).with_args(args),
            raises(exceptions.InvalidUsernamePassword),
        )

    def test_verify_auth_with_login_password_saml(self):
        self.set_authorized_authentication_method(s.login, 'saml')
        args = {'login': s.login, 'password': s.password}  # no saml_session_id

        self.ldap_user_backend.verify_password.return_value = True

        assert_that(
            calling(self.service.verify_auth).with_args(args),
            raises(exceptions.UnauthorizedAuthenticationMethod),
        )

    def test_verify_auth_saml_no_saml_session_id(self):
        self.saml_service.get_user_login_and_remove_context.return_value = None
        args = {'saml_session_id': s.saml_session_id}

        assert_that(
            calling(self.service.verify_auth).with_args(args),
            raises(exceptions.NoMatchingSAMLSession),
        )

    def test_verify_auth_saml(self):
        self.saml_service.get_user_login_and_remove_context.return_value = s.login
        self.set_authorized_authentication_method(s.login, 'saml')
        args = {'saml_session_id': s.saml_session_id}

        result = self.service.verify_auth(args)

        assert_that(result, contains_exactly(self.wazo_user_backend, s.login))
        assert_that(args, has_entries(login=s.login))

    def test_verify_auth_saml_not_authorized(self):
        self.saml_service.get_user_login_and_remove_context.return_value = s.login
        self.set_authorized_authentication_method(s.login, 'native')
        args = {'saml_session_id': s.saml_session_id}

        assert_that(
            calling(self.service.verify_auth).with_args(args),
            raises(exceptions.UnauthorizedAuthenticationMethod),
        )
