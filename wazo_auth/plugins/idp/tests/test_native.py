# Copyright 2019-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


from typing import cast
from unittest.mock import MagicMock

import pytest

from wazo_auth.exceptions import InvalidUsernamePassword
from wazo_auth.plugins.idp.native import Dependencies, NativeIDP


@pytest.fixture
def native_idp() -> NativeIDP:
    native_backend = MagicMock()
    dependencies = {
        'config': MagicMock(),
        'backends': {'wazo_user': native_backend},
    }
    native_idp = NativeIDP()
    native_idp.load(cast(Dependencies, dependencies))
    assert native_idp.loaded
    return native_idp


def test_can_authenticate(native_idp: NativeIDP):
    # login + password is ok
    assert native_idp.can_authenticate({'login': 'user', 'password': 'pass'})
    # no password not ok
    assert not native_idp.can_authenticate({'login': 'user'})
    # no login not ok
    assert not native_idp.can_authenticate({'password': 'pass'})
    # nothing not ok
    assert not native_idp.can_authenticate({})


def test_verify_auth_ok(native_idp: NativeIDP):
    args = {'login': 'user', 'password': 'pass'}

    # assume backend validates password
    native_idp._backend.verify_password.return_value = True

    backend, login = native_idp.verify_auth(args)
    assert backend
    assert login == args['login']


def test_verify_auth_bad_credentials(native_idp: NativeIDP):
    args = {'login': 'user', 'password': 'pass'}

    # assume backend rejects password
    native_idp._backend.verify_password.return_value = False

    with pytest.raises(InvalidUsernamePassword):
        native_idp.verify_auth(args)
