# Copyright 2019-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


from typing import cast
from unittest.mock import MagicMock
from unittest.mock import sentinel as s

import pytest

from wazo_auth.exceptions import NoMatchingSAMLSession
from wazo_auth.plugins.idp.saml import SAMLIDP, Dependencies


@pytest.fixture
def saml_idp() -> SAMLIDP:
    native_backend = MagicMock()
    saml_service = MagicMock()

    dependencies = {
        'config': {},
        'backends': {'wazo_user': MagicMock(obj=native_backend)},
        'saml_service': saml_service,
    }

    idp = SAMLIDP()
    idp.load(cast(Dependencies, dependencies))
    return idp


def test_can_authenticate(saml_idp: SAMLIDP):
    # refresh token + client id is ok
    assert saml_idp.can_authenticate({'saml_session_id': s.saml_session_id})
    # no saml_session_id not ok
    assert not saml_idp.can_authenticate({'something': 'else'})
    assert not saml_idp.can_authenticate({})


def test_verify_auth_ok(saml_idp: SAMLIDP):
    args = {'saml_session_id': s.saml_session_id}

    # assume saml_session_id exists and is valid
    saml_idp._saml_service.get_user_login.return_value = s.login

    backend, login = saml_idp.verify_auth(args)
    assert backend == saml_idp._backend
    assert login == s.login


def test_verify_auth_bad_credentials(saml_idp: SAMLIDP):
    args = {'saml_session_id': s.saml_session_id}

    # assume saml_session_id doesn't exist
    saml_idp._saml_service.get_user_login.side_effect = NoMatchingSAMLSession(
        s.saml_session_id
    )

    with pytest.raises(NoMatchingSAMLSession):
        saml_idp.verify_auth(args)
