# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime, timezone

from hamcrest import assert_that, calling, is_, not_, raises

from wazo_auth import exceptions
from wazo_auth.services.saml import RequestId, SamlAuthContext

from .helpers import base, fixtures

REQUEST_ID = 'id-6Ac62w7PS9rp1EC5e'


@base.use_asset('database')
class TestSAMLSessionDAO(base.DAOTestCase):
    @fixtures.db.saml_session(REQUEST_ID, session_id='samsid', domain='test.domain.org')
    def test_get(self, session_tuple: tuple[RequestId, SamlAuthContext]) -> None:
        (request_id, session) = self._saml_session_dao.get(REQUEST_ID)
        assert_that(request_id, is_(REQUEST_ID))
        assert_that(session.saml_session_id, is_('samsid'))
        assert_that(session.domain, is_('test.domain.org'))

    def test_create(self) -> None:
        now = datetime.now(timezone.utc)
        saml_session = SamlAuthContext(
            saml_session_id='samsid',
            domain='test.domain.org',
            login='login',
            redirect_url='acs-url',
            relay_state='relay-state',
            start_time=now,
        )
        self._saml_session_dao.create(REQUEST_ID, saml_session)
        (request_id, result_session) = self._saml_session_dao.get(REQUEST_ID)
        assert_that(request_id, is_(REQUEST_ID))
        assert_that(result_session.saml_session_id, is_('samsid'))
        assert_that(result_session.domain, is_('test.domain.org'))
        assert_that(result_session.login, is_('login'))
        assert_that(result_session.redirect_url, is_('acs-url'))
        assert_that(result_session.relay_state, is_('relay-state'))
        assert_that(result_session.start_time, is_(now))

        assert_that(
            calling(self._saml_session_dao.create).with_args(REQUEST_ID, saml_session),
            raises(exceptions.DuplicatedSAMLSessionException),
        )

    @fixtures.db.saml_session(REQUEST_ID)
    def test_update(
        self, saml_session_tuple: tuple[RequestId, SamlAuthContext]
    ) -> None:
        (request_id, session) = self._saml_session_dao.get(REQUEST_ID)
        assert session.login is None, 'Failed pre-requisite'
        self._saml_session_dao.update(request_id, login='test_login')
        _, updated = self._saml_session_dao.get(request_id)
        assert_that(updated.login, is_('test_login'))

        assert_that(
            calling(self._saml_session_dao.update).with_args('id-unknown'),
            raises(exceptions.UnknownSAMLSessionException),
        )

    @fixtures.db.saml_session(REQUEST_ID)
    def test_delete(self, _) -> None:
        assert_that(
            calling(self._saml_session_dao.delete).with_args('id-unknown'),
            not_(raises(Exception)),
        )
        assert_that(
            calling(self._saml_session_dao.delete).with_args(REQUEST_ID),
            not_(raises(Exception)),
        )
