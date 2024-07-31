# Copyright 2019-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
from typing import Any, Optional
from unittest import TestCase
from unittest.mock import Mock, patch

from hamcrest import assert_that, is_
from saml2.response import VerificationError

from wazo_auth import exceptions
from wazo_auth.config import _DEFAULT_CONFIG
from wazo_auth.database.queries import DAO
from wazo_auth.database.queries.saml_session import SAMLSessionDAO
from wazo_auth.services.tenant import TenantService

from ..saml import SamlAuthContext, SAMLService, SamlSessionItem


class TestSAMLService(TestCase):
    def setUp(self) -> None:
        self.lifetime = 10
        self.config: dict[str, Any] = _DEFAULT_CONFIG
        self.config['saml']['saml_session_lifetime_seconds'] = self.lifetime
        self.tenant_service_mock = Mock(TenantService)
        self.dao_mock = Mock(DAO)
        self.dao_mock.saml_session = Mock(SAMLSessionDAO)
        self.service = SAMLService(self.config, self.tenant_service_mock, self.dao_mock)

    def _get_auth_context(
        self,
        saml_id: str = 'saml_id',
        redirect_url: str = 'some_url',
        domain: str = 'some_domain',
        login: Optional[str] = None,
        relay_state: str = '6pruzvCdQHaLWCd30T6IziZFX_U=',
        date: datetime = datetime.fromisoformat('2000-01-01 00:00:02+00:00'),
    ) -> SamlAuthContext:
        return SamlAuthContext(saml_id, redirect_url, domain, relay_state, login, date)

    def test_clean_pending_requests(self) -> None:
        expired_date: datetime = datetime.fromisoformat('2000-01-01 00:00:00+00:00')
        expired: SamlAuthContext = self._get_auth_context(date=expired_date)

        pending_date: datetime = datetime.fromisoformat('2000-01-01 00:00:02+00:00')
        pending: SamlAuthContext = self._get_auth_context(date=pending_date)
        self.dao_mock.saml_session.list.return_value = [
            SamlSessionItem('id1', expired),
            SamlSessionItem('id2', pending),
        ]

        now: datetime = datetime.fromisoformat('2000-01-01 00:00:11+00:00')
        self.service.clean_pending_requests(now)

        self.dao_mock.saml_session.delete.assert_called_once_with('id1')

    @patch('wazo_auth.services.SAMLService.get_client')
    def test_create_session_on_sso_init(self, mock_get_client) -> None:
        url = 'url1'
        domain = 'ex.com'
        mock_client = Mock()
        mock_client.prepare_for_authenticate.return_value = 'id1', {
            'headers': [('Location', 'redirect_url')]
        }
        mock_get_client.return_value = mock_client

        self.service.prepare_redirect_response(url, domain)
        self.dao_mock.saml_session.create.assert_called_once()
        args = self.dao_mock.saml_session.create.call_args.args
        item: SamlSessionItem = args[0]
        assert_that(item.auth_context.redirect_url, is_(url))
        assert_that(item.auth_context.domain, is_(domain))

    @patch('wazo_auth.services.SAMLService.get_client')
    def test_enrich_context_on_successful_login(self, mock_get_client) -> None:
        domain = 'domain1'
        req_key = 'kid1'
        cached_req: SamlAuthContext = self._get_auth_context(domain=domain)
        pending_session = SamlSessionItem(req_key, cached_req)
        self.dao_mock.saml_session.list.return_value = [pending_session]
        self.dao_mock.saml_session.get.return_value = pending_session

        response = Mock()
        response.ava = {'name': ['testname']}
        name_id = (
            '<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            'testname</saml:NameID>'
        )
        response.name_id = name_id
        response.session_id.return_value = req_key
        mock_client = Mock()
        mock_client.parse_authn_request_response.return_value = response
        mock_get_client.return_value = mock_client

        self.service.process_auth_response(
            'url',
            'remote_addr',
            {'RelayState': cached_req.relay_state, 'SAMLResponse': None},
        )

        _, args, _ = mock_get_client.mock_calls[0]
        assert_that(args[0], is_(domain))

        update: dict[str, str] = {'login': 'testname', 'saml_name_id': name_id}
        self.dao_mock.saml_session.update.assert_called_once_with(req_key, **update)

    @patch('wazo_auth.services.SAMLService.get_client')
    def test_remove_session_if_relay_state_is_not_in_outstanding_requests(
        self, mock_get_client
    ) -> None:
        domain = 'domain1'
        req_key = 'kid1'
        saml_id = 'sid1'
        s_relay_state = '6pruzvCdQHaLWCd30T6IziZFX_U=outstanding'
        saved_req: SamlAuthContext = self._get_auth_context(
            saml_id=saml_id, domain=domain, relay_state=s_relay_state
        )
        pending_session = SamlSessionItem(req_key, saved_req)

        def mocked_list(session_id=None, relay_state=None) -> list[SamlSessionItem]:
            rs = [pending_session] if relay_state == s_relay_state else []
            sid = [pending_session] if session_id == saml_id else []
            return rs + sid

        self.dao_mock.saml_session.list.side_effect = mocked_list

        response = Mock()
        response.session_id.return_value = req_key
        mock_client = Mock()
        mock_client.parse_authn_request_response.return_value = response
        mock_get_client.return_value = mock_client
        with self.assertRaises(exceptions.SAMLProcessingError) as eo:
            self.service.process_auth_response(
                'url',
                'remote_addr',
                {
                    'RelayState': 'iO6ldOVHIIpUKg6I8AyeZSCHEcQ=outstanding',
                    'SAMLResponse': None,
                },
            )

        the_exception = eo.exception
        self.assertEqual(the_exception.status_code, 404)

    @patch('wazo_auth.services.SAMLService.get_client')
    def test_remove_session_if_relay_state_does_not_correspond_to_session_relay_state(
        self, mock_get_client
    ) -> None:
        domain = 'domain1'
        req_key = 'kid1'
        s_relay_state = '6pruzvCdQHaLWCd30T6IziZFX_U=relay'
        original_req: SamlAuthContext = self._get_auth_context(
            domain=domain, relay_state=s_relay_state
        )
        altered_relay_state = 'iO6ldOVHIIpUKg6I8AyeZSCHEcQ=relay'

        pending_session = SamlSessionItem(req_key, original_req)

        def mocked_list(session_id=None, relay_state=None) -> list[SamlSessionItem]:
            return [pending_session] if relay_state == s_relay_state else []

        self.dao_mock.saml_session.list.side_effect = mocked_list
        self.dao_mock.saml_session.get.return_value = SamlSessionItem(
            req_key, original_req
        )

        response = Mock()
        response.session_id.return_value = req_key
        mock_client = Mock()
        mock_client.parse_authn_request_response.return_value = response
        mock_get_client.return_value = mock_client
        with self.assertRaises(exceptions.SAMLProcessingError) as eo:
            self.service.process_auth_response(
                'url',
                'remote_addr',
                {'RelayState': altered_relay_state, 'SAMLResponse': None},
            )

        the_exception = eo.exception
        self.assertEqual(the_exception.status_code, 404)

    @patch('wazo_auth.services.SAMLService.get_client')
    def test_process_response_raise_exception_with_redirection_url_when_possible(
        self, mock_get_client
    ) -> None:
        domain = 'domain1'
        req_key = 'kid1'
        req: SamlAuthContext = self._get_auth_context(
            domain=domain,
            relay_state='6pruzvCdQHaLWCd30T6IziZFX_U=',
            redirect_url='redirect_url',
        )

        pending_session = SamlSessionItem(req_key, req)
        self.dao_mock.saml_session.list.return_value = [pending_session]
        self.dao_mock.saml_session.get.return_value = SamlSessionItem(req_key, req)

        response = Mock()
        response.session_id.return_value = req_key
        mock_client = Mock()
        mock_client.parse_authn_request_response.side_effect = VerificationError
        mock_get_client.return_value = mock_client
        with self.assertRaises(exceptions.SAMLProcessingErrorWithReturnURL) as eo:
            self.service.process_auth_response(
                'url',
                'remote_addr',
                {'RelayState': '6pruzvCdQHaLWCd30T6IziZFX_U=', 'SAMLResponse': None},
            )

        the_exception = eo.exception
        self.assertEqual(the_exception.status_code, 500)
        self.assertEqual(
            the_exception.redirect_url, 'redirect_url?login_failure_code=500'
        )
        self.dao_mock.saml_session.delete.assert_called_once_with(req_key)

    def test_get_user_login_and_remove_context(self) -> None:
        saml_context = SamlAuthContext(
            saml_session_id='session_1',
            redirect_url='rurl1',
            domain='domain1.org',
            relay_state='6pruzvCdQHaLWCd30T6IziZFX_U=',
            login='login_1',
        )
        ignored_saml_context = SamlAuthContext(
            saml_session_id='session2',
            redirect_url='rurl2',
            domain='domain2.org',
            relay_state='iO6ldOVHIIpUKg6I8AyeZSCHEcQ=',
            login='login2',
        )
        pending_session = SamlSessionItem('req_id', saml_context)
        ignored_session = SamlSessionItem('other_req_id', ignored_saml_context)
        sessions: dict[str, SamlSessionItem] = {
            pending_session.auth_context.saml_session_id: pending_session,
            ignored_session.auth_context.saml_session_id: ignored_session,
        }

        def mocked_list(session_id=None) -> list[SamlSessionItem]:
            if not session_id:
                return [pending_session, ignored_session]
            else:
                i: SamlSessionItem | None = sessions.get(session_id)
                return [i] if i else []

        self.dao_mock.saml_session.list.side_effect = mocked_list
        self.dao_mock.saml_session.get.return_value = pending_session

        samples = [
            ('unknown', None),
            (
                pending_session.auth_context.saml_session_id,
                pending_session.auth_context.login,
            ),
            ('another', None),
        ]
        for saml_session_id, expected in samples:
            result: str | None = self.service.get_user_login_and_remove_context(
                saml_session_id
            )
            assert_that(result, is_(expected))

        self.dao_mock.saml_session.delete.assert_called_once_with(
            pending_session.request_id
        )
