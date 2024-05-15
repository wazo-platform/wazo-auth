# Copyright 2019-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
from typing import Optional
from unittest import TestCase
from unittest.mock import Mock, patch

from hamcrest import assert_that, is_

from wazo_auth.config import _DEFAULT_CONFIG
from wazo_auth.services.tenant import TenantService

from ..saml import SamlAuthContext, SAMLService


class TestSAMLService(TestCase):
    def setUp(self):
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
        date: datetime = datetime.fromisoformat('2000-01-01 00:00:02'),
    ) -> SamlAuthContext:
        return SamlAuthContext(saml_id, redirect_url, domain, login, None, date)

    def test_clean_pending_requests(self):
        expired_date: datetime = datetime.fromisoformat('2000-01-01 00:00:02')
        expired: SamlAuthContext = self._get_auth_context(date=expired_date)

        pending_date: datetime = datetime.fromisoformat('2000-01-01 00:00:01')
        pending: SamlAuthContext = self._get_auth_context(date=pending_date)

        self.service._outstanding_requests = {'id1': expired, 'id2': pending}

        now: datetime = datetime.fromisoformat('2000-01-01 00:00:11')
        self.service.clean_pending_requests(now)

        assert_that(self.service._outstanding_requests, is_({'id2': pending}))

    @patch('wazo_auth.services.SAMLService.get_client')
    def test_create_session_on_sso_init(self, mock_get_client):
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
    def test_enrich_context_on_successful_login(self, mock_get_client):
        domain = 'domain1'
        req_key = 'kid1'
        cached_req = self._get_auth_context(domain=domain)
        self.service._outstanding_requests = {req_key: cached_req}

        response = Mock()
        response.ava = {'name': 'testname'}
        response.session_id.return_value = req_key
        mock_client = Mock()
        mock_client.parse_authn_request_response.return_value = response
        mock_get_client.return_value = mock_client

        self.service.process_auth_response(
            'url', 'remote_addr', {'RelayState': domain, 'SAMLResponse': None}
        )

        _, args, _ = mock_get_client.mock_calls[0]
        assert_that(args[0], is_(domain))
        assert_that(len(self.service._outstanding_requests), is_(1))
        updated_req: SamlAuthContext = self.service._outstanding_requests[req_key]
        assert_that(updated_req.login, is_('testname'))
        assert_that(updated_req.response, is_(response))

    def test_remove_context_data_on_login_retrieval(self):
        saml_id = 'sd1'
        req_key = 'kid1'
        login = 'user1'
        cached_req = self._get_auth_context(saml_id=saml_id, login=login)
        self.service._outstanding_requests = {req_key: cached_req}

        result = self.service.get_user_login_and_remove_context(saml_id)

        assert_that(result, is_(login))
        assert_that(len(self.service._outstanding_requests), is_(0))
