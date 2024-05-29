# Copyright 2020-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Any

from .helpers import base
from .helpers.base import assert_http_error_partial_body


@base.use_asset('base')
class TestSAML(base.APIIntegrationTest):
    def _expected_dict(
        self, message: str, error_id: str, resource: str, details: dict[str, Any] = None
    ) -> dict[str, Any]:
        return {
            'message': message,
            'error_id': error_id,
            'resource': resource,
            'details': details or {},
        }

    def test_sso_missing_redirect_url_param(self) -> None:
        assert_http_error_partial_body(
            400,
            self._expected_dict("redirect_url", 'invalid-data', 'saml'),
            self.client.saml.sso,
            domain='example.com',
            redirect_url=None,
        )

    def test_sso_missing_domain_param(self) -> None:
        assert_http_error_partial_body(
            400,
            self._expected_dict('domain', 'invalid-data', 'saml'),
            self.client.saml.sso,
            domain=None,
            redirect_url='https://example.com/acs',
        )

    def test_sso_unparsable_domain_param(self) -> None:
        assert_http_error_partial_body(
            400,
            self._expected_dict('domain', 'invalid-data', 'saml'),
            self.client.saml.sso,
            domain='notadomain',
            redirect_url='https://example.com/acs',
        )

    def test_sso_unknown_domain_for_tenant(self) -> None:
        assert_http_error_partial_body(
            500,
            self._expected_dict(
                'SAML client for domain not found or failed',
                'configuration-error',
                'saml',
                details={'domain': 'unknown.com'},
            ),
            self.client.saml.sso,
            domain='unknown.com',
            redirect_url='https://example.com/acs',
        )

    def test_acs_missing_saml_response_param(self) -> None:
        assert_http_error_partial_body(
            400,
            self._expected_dict(
                'RelayState and/or SAMLResponse', 'invalid-data', 'saml'
            ),
            self.client.saml.acs,
            saml_response=None,
            relay_state='state',
        )

    def test_acs_missing_relay_state_param(self) -> None:
        assert_http_error_partial_body(
            400,
            self._expected_dict(
                'RelayState and/or SAMLResponse', 'invalid-data', 'saml'
            ),
            self.client.saml.acs,
            saml_response='response',
            relay_state=None,
        )
