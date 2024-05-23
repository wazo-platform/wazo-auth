# Copyright 2016-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from typing import Any

import pytest
from playwright.sync_api import Page

from wazo_auth.database.queries.user import UserDAO

from .helpers import base
from .helpers.base import APIIntegrationTest


@base.use_asset('base')
class TestSamlService(APIIntegrationTest):
    @pytest.fixture(autouse=True)
    def setup(self, page: Page):
        self.page = page

    def setUp(self) -> None:
        self.login = os.environ['WAZO_SAML_LOGIN']
        self.password = os.environ['WAZO_SAML_PASSWORD']

    def _setup_tenant_and_domain(self, domain_name: str) -> None:
        self.tenant = self.client.tenants.new(
            name='example', slug='example', domain_names=[domain_name]
        )

    def _create_user(self, login: str) -> None:
        user: dict[str, Any] = {
            'username': login,
            'firstname': 'saml',
            'lastname': 'test user',
            'password_hash': 'hash',
            'password_salt': 'salt',
            'purpose': 'user',
            'enabled': True,
            'tenant_uuid': self.tenant['uuid'],
        }
        UserDAO().create(**user)
        self.session.commit()

    def _accept_self_signed_certificate_on_stack(self) -> None:
        self.page.goto("https://stack.wazo.local/api/auth/0.1/tokens")

    def _reload_saml_config(self) -> None:
        self.restart_auth()

    @pytest.mark.only_browser("chromium")
    @pytest.mark.browser_context_args(
        timezone_id="Europe/London", locale="en-GB", ignore_https_errors=True
    )
    @pytest.mark.browser_args(host_resolver_rules="MAP 127.0.0.1 *.wazo.local")
    def test_login(self) -> None:
        self._setup_tenant_and_domain("example.com")
        self._create_user(self.login)
        self._reload_saml_config()
        self._accept_self_signed_certificate_on_stack()
