# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime, timezone

from hamcrest import assert_that, calling, is_, not_, raises

from wazo_auth import exceptions
from wazo_auth.services.saml import SamlAuthContext, SamlSessionItem

from .helpers import base, fixtures

REQUEST_ID = 'id-6Ac62w7PS9rp1EC5e'


@base.use_asset('database')
class TestSAMLSessionDAO(base.DAOTestCase):
    @fixtures.db.saml_session(REQUEST_ID, session_id='samsid', domain='test.domain.org')
    def test_get(self, _: SamlSessionItem) -> None:
        item: SamlSessionItem = self._saml_session_dao.get(REQUEST_ID)
        assert_that(item.request_id, is_(REQUEST_ID))
        assert_that(item.auth_context.saml_session_id, is_('samsid'))
        assert_that(item.auth_context.domain, is_('test.domain.org'))

    @fixtures.db.saml_session(REQUEST_ID, session_id='samsid', domain='test.domain.org')
    @fixtures.db.saml_session('2nd-request-id')
    def test_list(self, a, b) -> None:
        all: list[SamlSessionItem] = self._saml_session_dao.list()
        assert_that(len(all), is_(2))
        assert_that(all[0].request_id, is_(REQUEST_ID))
        assert_that(all[1].request_id, is_('2nd-request-id'))
        assert_that(all[0].auth_context.saml_session_id, is_('samsid'))

    def test_create(self) -> None:
        now = datetime.now(timezone.utc)
        auth_context = SamlAuthContext(
            saml_session_id='samsid',
            domain='test.domain.org',
            login='login',
            redirect_url='acs-url',
            relay_state='relay-state',
            start_time=now,
        )
        self._saml_session_dao.create(SamlSessionItem(REQUEST_ID, auth_context))
        (request_id, result_session) = self._saml_session_dao.get(REQUEST_ID)
        assert_that(request_id, is_(REQUEST_ID))
        assert_that(result_session.saml_session_id, is_('samsid'))
        assert_that(result_session.domain, is_('test.domain.org'))
        assert_that(result_session.login, is_('login'))
        assert_that(result_session.redirect_url, is_('acs-url'))
        assert_that(result_session.relay_state, is_('relay-state'))
        assert_that(result_session.start_time, is_(now))

        assert_that(
            calling(self._saml_session_dao.create).with_args(
                SamlSessionItem(REQUEST_ID, auth_context)
            ),
            raises(exceptions.DuplicatedSAMLSessionException),
        )

    @fixtures.db.saml_session(REQUEST_ID)
    def test_update(self, _: SamlSessionItem) -> None:
        item: SamlSessionItem = self._saml_session_dao.get(REQUEST_ID)
        assert item.auth_context.login is None, 'Failed pre-requisite'
        self._saml_session_dao.update(item.request_id, login='test_login')
        updated: SamlSessionItem = self._saml_session_dao.get(item.request_id)
        assert_that(updated.auth_context.login, is_('test_login'))

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
