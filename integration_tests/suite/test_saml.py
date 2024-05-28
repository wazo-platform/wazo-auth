# Copyright 2020-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from .helpers import base
from .helpers.base import assert_http_error

@base.use_asset('base')
class TestSAML(base.APIIntegrationTest):
    def test_sso_missing_redirect_url(self):
        assert_http_error(
            400,
            self.client.saml.sso,
            domain='only_domain',
            redirect_url=None            
        )
        
    def test_sso_missing_domain(self):
        assert_http_error(
            400,
            self.client.saml.sso,
            domain=None,
            redirect_url='https://example.com/acs'
        )

    def test_sso_unparsable_domain(self):
        assert_http_error(
            400,
            self.client.saml.sso,
            domain='notadomain',
            redirect_url='https://example.com/acs'
        )

    def test_sso_unknown_domain_for_tenant(self):
        assert_http_error(
            500,
            self.client.saml.sso,
            domain='unknown.com',
            redirect_url='https://example.com/acs'
        )

    def test_acs_missing_response(self):
        assert_http_error(
            400,
            self.client.saml.acs,
            response=None,
            token='token'
        )
        
    def test_acs_missing_token(self):
        assert_http_error(
            400,
            self.client.saml.acs,
            response='response',
            token=None            
        )
