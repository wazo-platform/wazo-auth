# Copyright 2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


from typing import cast
from unittest.mock import MagicMock
from unittest.mock import sentinel as s

import pytest

from wazo_auth.exceptions import UnauthorizedAuthenticationMethod, UnknownRefreshToken
from wazo_auth.plugins.idp.refresh_token import Dependencies, RefreshTokenIDP


class CustomIDP:
    authentication_method = 'custom'
    loaded = False

    def load(self, dependencies: Dependencies):
        self.loaded = True

    def get_backend(self, args):
        return s.custom_idp_backend


@pytest.fixture
def refresh_token_idp() -> RefreshTokenIDP:
    user_service = MagicMock()
    tenant_service = MagicMock()
    native_backend = MagicMock()
    token_service = MagicMock()
    dependencies = {
        'user_service': user_service,
        'group_service': MagicMock(),
        'tenant_service': tenant_service,
        'token_service': token_service,
        'ldap_service': MagicMock(),
        'config': MagicMock(),
        'backends': {'wazo_user': native_backend},
        'idp_plugins': {
            'custom': MagicMock(obj=CustomIDP()),
        },
        'native_idp': MagicMock(
            obj=MagicMock(
                authentication_method='native',
                get_backend=MagicMock(return_value=native_backend),
            )
        ),
    }
    refresh_token_idp = RefreshTokenIDP()
    refresh_token_idp.load(cast(Dependencies, dependencies))
    return refresh_token_idp


def test_can_authenticate(refresh_token_idp: RefreshTokenIDP):
    # refresh token + client id is ok
    assert refresh_token_idp.can_authenticate(
        {'refresh_token': s.refresh_token, 'client_id': s.client_id}
    )
    # no refresh token not ok
    assert not refresh_token_idp.can_authenticate({'client_id': s.client_id})
    # no client id not ok
    assert not refresh_token_idp.can_authenticate({'refresh_token': s.refresh_token})
    # nothing not ok
    assert not refresh_token_idp.can_authenticate({})
    # login + password not ok
    assert not refresh_token_idp.can_authenticate({'login': 'user', 'password': 'pass'})


def test_verify_auth_ok(refresh_token_idp: RefreshTokenIDP):
    args = {'refresh_token': s.refresh_token, 'client_id': s.client_id}

    # assume user has native auth method
    user = MagicMock()
    user.uuid = 'user_uuid'
    user.authentication_method = 'native'
    refresh_token_idp._user_service.get_user_by_login.return_value = user

    # assume refresh token exists and is valid
    refresh_token_idp._token_service.get_refresh_token_info.return_value = {
        'login': s.login,
        'backend': 'native',
    }

    backend, login = refresh_token_idp.verify_auth(args)
    assert backend
    assert login == s.login


def test_verify_auth_bad_auth_method(refresh_token_idp: RefreshTokenIDP):
    args = {'refresh_token': s.refresh_token, 'client_id': s.client_id}

    # assume user do not have native auth method
    user = MagicMock()
    user.uuid = 'user_uuid'
    user.authentication_method = 'something'
    refresh_token_idp._user_service.get_user_by_login.return_value = user

    with pytest.raises(UnauthorizedAuthenticationMethod):
        refresh_token_idp.verify_auth(args)


def test_verify_auth_bad_credentials(refresh_token_idp: RefreshTokenIDP):
    args = {'refresh_token': s.refresh_token, 'client_id': s.client_id}

    # assume refresh token doesn't exist
    refresh_token_idp._token_service.get_refresh_token_info.side_effect = (
        UnknownRefreshToken(s.client_id)
    )

    with pytest.raises(UnknownRefreshToken):
        refresh_token_idp.verify_auth(args)


def test_verify_auth_idp_auth_method(refresh_token_idp: RefreshTokenIDP):
    args = {'refresh_token': s.refresh_token, 'client_id': s.client_id}

    # assume user do not have native auth method
    user = MagicMock()
    user.uuid = 'user_uuid'
    user.authentication_method = 'custom'
    refresh_token_idp._user_service.get_user_by_login.return_value = user

    refresh_token_idp._token_service.get_refresh_token_info.return_value = {
        'login': s.login
    }

    backend, login = refresh_token_idp.verify_auth(args)

    assert backend == s.custom_idp_backend
    assert login == s.login
