# Copyright 2016-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json
from typing import Any

import pytest
from playwright.sync_api import qPage, expect

from wazo_auth.database.queries.user import UserDAO

from .helpers import base
from .helpers.base import APIIntegrationTest


@base.use_asset('base')
class TestSamlService(APIIntegrationTest):
    @pytest.fixture(autouse=True)
    def setup(self, page: Page):
        self.page = page
        try:
            saml_test_config = json.load(open('assets/saml/config/saml.json'))
            self.login = saml_test_config['login']
            self.password = saml_test_config['password']
        except FileNotFoundError as e:
            pytest.fail(f"Unable to load SAML test config ({e})")
        except ValueError as e:
            pytest.fail(f"Unable to parse SAML test config credentials ({e})")
        except Exception as e:
            pytest.fail(f"Unexpected error while loading SAML test config ({e})")

    def _setup_tenant_and_domain(self, domain_name: str) -> None:
        self.tenant = self.client.tenants.new(
            name='example', slug='example', domain_names=[domain_name]
        )

    def _create_user(self, login: str) -> None:
        user: dict[str, Any] = {
            'username': login,
            'firstname': 'saml',
            'lastname': 'test user',
            'password_hash': 'hash',  # NOSONAR
            'password_salt': 'salt',  # NOSONAR
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

    def _click_login(self, page):
        page.goto("https://app.wazo.local/")
        expect(page.locator("h1"), "Error while opening the test page").to_contain_text(
            "Wazo SAML login"
        )
        search_login_btn: str = '#login_btn'
        page.wait_for_selector(search_login_btn)
        page.click(search_login_btn)
        expect(page, "Unable to get Microsoft login page").to_have_title(
            "Sign in to your account"
        )

    def _login(self, page, login, password):
        page.get_by_placeholder("Email address, phone number").fill(login)
        page.get_by_role("button", name="Next").click()
        expect(page.get_by_role("heading"), "Failed to submit login").to_contain_text(
            "Enter password"
        )
        page.get_by_placeholder("Password").fill(password)
        page.get_by_role("button", name="Sign in").click()
        expect(
            page.get_by_role("heading"), "Failed to submit password"
        ).to_contain_text("Stay signed in?")
        page.get_by_role("button", name="No").click()

    @pytest.mark.only_browser("chromium")
    @pytest.mark.browser_context_args(
        timezone_id="Europe/London", locale="en-GB", ignore_https_errors=True
    )
    def test_login(self) -> None:
        self._setup_tenant_and_domain("example.com")
        self._create_user(self.login)
        self._reload_saml_config()
        self._accept_self_signed_certificate_on_stack()
        self._click_login(self.page)
        self._login(self.page, self.login, self.password)
        expect(self.page.locator("h1"), "SSO handling failed").to_contain_text(
            "Wazo SAML Post ACS handling"
        )
        expect(
            self.page.locator("#token"), "Failed to retrieve token"
        ).not_to_contain_text("not yet known")
