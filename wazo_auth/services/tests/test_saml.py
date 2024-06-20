# Copyright 2019-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
from typing import Optional
from unittest import TestCase
from unittest.mock import Mock, patch
from unittest.mock import sentinel as s

from hamcrest import assert_that, has_length, is_

from wazo_auth.config import _DEFAULT_CONFIG
from wazo_auth.services.tenant import TenantService

from ..saml import SamlAuthContext, SAMLService


class TestSAMLService(TestCase):
    def setUp(self) -> None:
        self.lifetime = 10
        self.config = _DEFAULT_CONFIG
        self.config['saml']['saml_session_lifetime_seconds'] = self.lifetime
        self.tenant_service_mock = Mock(TenantService)
        self.service = SAMLService(self.config, self.tenant_service_mock)

    def _get_auth_context(
        self,
        saml_id: str = 'saml_id',
        redirect_url: str = 'some_url',
        domain: str = 'some_domain',
        login: Optional[str] = None,
        relay_state: str = '6pruzvCdQHaLWCd30T6IziZFX_U=',
        date: datetime = datetime.fromisoformat('2000-01-01 00:00:02+00:00'),
    ) -> SamlAuthContext:
        return SamlAuthContext(
            saml_id, redirect_url, domain, relay_state, login, None, date
        )

    def test_clean_pending_requests(self) -> None:
        expired_date: datetime = datetime.fromisoformat('2000-01-01 00:00:00+00:00')
        expired: SamlAuthContext = self._get_auth_context(date=expired_date)

        pending_date: datetime = datetime.fromisoformat('2000-01-01 00:00:02+00:00')
        pending: SamlAuthContext = self._get_auth_context(date=pending_date)

        self.service._outstanding_requests = {'id1': expired, 'id2': pending}

        now: datetime = datetime.fromisoformat('2000-01-01 00:00:11+00:00')
        self.service.clean_pending_requests(now)

        assert_that(self.service._outstanding_requests, is_({'id2': pending}))

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
        assert_that(len(self.service._outstanding_requests), is_(1))
        cached_req: SamlAuthContext = list(self.service._outstanding_requests.values())[
            0
        ]
        assert_that(cached_req.redirect_url, is_(url))
        assert_that(cached_req.domain, is_(domain))

    @patch('wazo_auth.services.SAMLService.get_client')
    def test_enrich_context_on_successful_login(self, mock_get_client) -> None:
        domain = 'domain1'
        req_key = 'kid1'
        cached_req: SamlAuthContext = self._get_auth_context(domain=domain)
        self.service._outstanding_requests = {req_key: cached_req}

        response = Mock()
        response.ava = {'name': ['testname']}
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
        assert_that(len(self.service._outstanding_requests), is_(1))
        updated_req: SamlAuthContext = self.service._outstanding_requests[req_key]
        assert_that(updated_req.login, is_('testname'))
        assert_that(updated_req.response, is_(response))

    @patch('wazo_auth.services.SAMLService.get_client')
    def test_remove_session_if_relay_state_is_not_in_outstanding_requests(
        self, mock_get_client
    ) -> None:
        domain = 'domain1'
        req_key = 'kid1'
        saved_req: SamlAuthContext = self._get_auth_context(
            domain=domain, relay_state='6pruzvCdQHaLWCd30T6IziZFX_U='
        )

        self.service._outstanding_requests = {req_key: saved_req}

        response = Mock()
        response.session_id.return_value = req_key
        mock_client = Mock()
        mock_client.parse_authn_request_response.return_value = response
        mock_get_client.return_value = mock_client
        res = self.service.process_auth_response(
            'url',
            'remote_addr',
            {'RelayState': 'iO6ldOVHIIpUKg6I8AyeZSCHEcQ=', 'SAMLResponse': None},
        )

        assert_that(res, is_(None))
        assert_that(self.service._outstanding_requests, is_({req_key: saved_req}))

    @patch('wazo_auth.services.SAMLService.get_client')
    def test_remove_session_if_relay_state_does_not_correspond_to_session_relay_state(
        self, mock_get_client
    ) -> None:
        domain = 'domain1'
        req_key = 'kid1'
        original_req: SamlAuthContext = self._get_auth_context(
            domain=domain, relay_state='6pruzvCdQHaLWCd30T6IziZFX_U='
        )
        altered_req: SamlAuthContext = self._get_auth_context(
            domain=domain, relay_state='iO6ldOVHIIpUKg6I8AyeZSCHEcQ='
        )

        self.service._outstanding_requests = {
            req_key: original_req,
            "other_key": altered_req,
        }

        response = Mock()
        response.session_id.return_value = req_key
        mock_client = Mock()
        mock_client.parse_authn_request_response.return_value = response
        mock_get_client.return_value = mock_client
        res = self.service.process_auth_response(
            'url',
            'remote_addr',
            {'RelayState': 'iO6ldOVHIIpUKg6I8AyeZSCHEcQ=', 'SAMLResponse': None},
        )

        assert_that(res, is_(None))
        assert_that(len(self.service._outstanding_requests), is_(2))

    def test_get_user_login_and_remove_context(self) -> None:
        saml_context = SamlAuthContext(
            saml_session_id=s.session_1,
            redirect_url=s.redirect_url,
            domain=s.domain,
            relay_state='6pruzvCdQHaLWCd30T6IziZFX_U=',
            login=s.login_1,
        )
        ignored_saml_context = SamlAuthContext(
            s.session2,
            s.redirect_url,
            s.domain,
            'iO6ldOVHIIpUKg6I8AyeZSCHEcQ=',
            s.login2,
        )

        self.service._outstanding_requests = {
            s.req_id: saml_context,
            s.other_req_id: ignored_saml_context,
        }
        samples = [
            ('unknown', None),
            (s.session_1, s.login_1),
            (None, None),
        ]
        for saml_session_id, expected in samples:
            result: str | None = self.service.get_user_login_and_remove_context(
                saml_session_id
            )
            assert_that(result, is_(expected))

        assert_that(self.service._outstanding_requests, has_length(1))
