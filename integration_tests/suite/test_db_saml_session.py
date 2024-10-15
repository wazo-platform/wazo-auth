# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime, timezone

from hamcrest import (
    assert_that,
    calling,
    contains_exactly,
    has_properties,
    is_,
    not_,
    raises,
)

from wazo_auth import exceptions
from wazo_auth.services.saml import SamlAuthContext, SamlSessionItem

from .helpers import base, fixtures

REQUEST_ID = 'id-6Ac62w7PS9rp1EC5e'


@base.use_asset('database')
class TestSAMLSessionDAO(base.DAOTestCase):
    @fixtures.db.saml_session(REQUEST_ID, session_id='samsid', domain='test.domain.org')
    def test_get(self, fixture: SamlSessionItem) -> None:
        item: SamlSessionItem = self._saml_session_dao.get(REQUEST_ID)
        assert_that(item, is_(fixture))

    @fixtures.db.saml_session(REQUEST_ID, session_id='samsid', domain='test.domain.org')
    @fixtures.db.saml_session('2nd-request-id')
    def test_list(self, a, b) -> None:
        all_sessions: list[SamlSessionItem] = self._saml_session_dao.list()
        assert_that(len(all_sessions), is_(2))
        assert_that(all_sessions[0], is_(a))
        assert_that(all_sessions[1], is_(b))

    @fixtures.db.saml_session(REQUEST_ID, session_id='samsid')
    @fixtures.db.saml_session('2nd-request-id', session_id='autre_id')
    def test_list_with_filter_session_id(self, a, b) -> None:
        matching_sessions: list[SamlSessionItem] = self._saml_session_dao.list(
            session_id=a.auth_context.saml_session_id
        )
        assert_that(
            matching_sessions,
            contains_exactly(
                has_properties(
                    request_id=REQUEST_ID,
                    auth_context=has_properties(
                        saml_session_id=a.auth_context.saml_session_id
                    ),
                ),
            ),
        )

    @fixtures.db.saml_session(REQUEST_ID, relay_state='r1')
    @fixtures.db.saml_session('2nd-request-id', relay_state='autre_r')
    def test_list_with_filter_relay_state(self, a, b) -> None:
        matching_sessions: list[SamlSessionItem] = self._saml_session_dao.list(
            relay_state=b.auth_context.relay_state
        )
        assert_that(
            matching_sessions,
            contains_exactly(
                has_properties(
                    request_id='2nd-request-id',
                    auth_context=has_properties(relay_state=b.auth_context.relay_state),
                ),
            ),
        )

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
        assert_that(result_session, is_(auth_context))

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

        assert_that(self._saml_session_dao.list(), is_([]))
