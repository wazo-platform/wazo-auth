# Copyright 2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


from typing import cast
from unittest.mock import MagicMock
from unittest.mock import sentinel as s

import pytest

from wazo_auth.exceptions import InvalidUsernamePassword
from wazo_auth.plugins.idp.ldap import LDAPIDP, Dependencies


@pytest.fixture
def ldap_idp() -> LDAPIDP:
    ldap_backend = MagicMock()

    dependencies = {
        'config': {},
        'backends': {'ldap_user': MagicMock(obj=ldap_backend)},
    }

    idp = LDAPIDP()
    idp.load(cast(Dependencies, dependencies))
    return idp


def test_can_authenticate(ldap_idp: LDAPIDP):
    # valid LDAP auth parameters
    assert ldap_idp.can_authenticate(
        {
            'login': s.login,
            'password': s.password,
            'domain_name': s.domain_name,
        }
    )
    assert ldap_idp.can_authenticate(
        {
            'login': s.login,
            'password': s.password,
            'tenant_id': s.tenant_id,
        }
    )
    # missing required parameters
    assert not ldap_idp.can_authenticate(
        {
            'login': s.login,
            'password': s.password,
        }
    )

    assert not ldap_idp.can_authenticate(
        {
            'login': s.login,
            'domain_name': s.domain_name,
            'tenant_id': s.tenant_id,
        }
    )

    assert not ldap_idp.can_authenticate({})


def test_verify_auth_domain_name_ok(ldap_idp: LDAPIDP):
    args = {
        'login': s.login,
        'password': s.password,
        'domain_name': s.domain_name,
    }

    # Assume backend verifies password successfully
    def update_args(login, password, args):
        args['user_email'] = s.email
        return True

    ldap_idp._backend.verify_password.side_effect = update_args

    backend, login = ldap_idp.verify_auth(args)
    assert backend == ldap_idp._backend
    assert login == s.email

    # Verify the backend was called with the correct parameters
    ldap_idp._backend.verify_password.assert_called_once_with(s.login, s.password, args)


def test_verify_auth_domain_name_bad_credentials(ldap_idp: LDAPIDP):
    args = {
        'login': s.login,
        'password': s.password,
        'domain_name': s.domain_name,
        'user_email': s.email,
    }

    # Assume backend fails to verify password
    ldap_idp._backend.verify_password.return_value = False

    with pytest.raises(InvalidUsernamePassword):
        ldap_idp.verify_auth(args)


def test_verify_auth_tenant_id_ok(ldap_idp: LDAPIDP):
    args = {
        'login': s.login,
        'password': s.password,
        'tenant_id': s.tenant_id,
    }

    # Assume backend verifies password successfully
    def update_args(login, password, args):
        args['user_email'] = s.email
        return True

    ldap_idp._backend.verify_password.side_effect = update_args

    backend, login = ldap_idp.verify_auth(args)
    assert backend == ldap_idp._backend
    assert login == s.email

    # Verify the backend was called with the correct parameters
    ldap_idp._backend.verify_password.assert_called_once_with(s.login, s.password, args)


def test_verify_auth_tenant_id_bad_credentials(ldap_idp: LDAPIDP):
    args = {
        'login': s.login,
        'password': s.password,
        'tenant_id': s.tenant_id,
        'user_email': s.email,
    }

    # Assume backend fails to verify password
    ldap_idp._backend.verify_password.return_value = False

    with pytest.raises(InvalidUsernamePassword):
        ldap_idp.verify_auth(args)
