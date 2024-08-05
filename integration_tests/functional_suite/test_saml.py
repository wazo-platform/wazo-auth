# Copyright 2016-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import os
import pathlib
from typing import Any

import pytest
from playwright.sync_api import Page, expect

from wazo_auth.database.queries.user import UserDAO

from .helpers import base
from .helpers.base import SAMLIntegrationTest


class RedactedValue:
    def __init__(self, value):
        self._value = value

    def __repr__(self):
        return "*Redacted****"

    def __str___(self):
        return "*Redacted****"


@base.use_asset('saml')
class TestSamlService(SAMLIntegrationTest):
    @pytest.fixture(autouse=True)
    def setup(self, page: Page) -> None:
        self.page = page
        if 'WAZO_SAML_CONFIG_FILE' in os.environ:
            conf_file = pathlib.Path(os.environ['WAZO_SAML_CONFIG_FILE'])
        else:
            conf_file = (
                pathlib.Path(__file__).parent.parent / 'assets/saml/config/saml.json'
            )
        if conf_file.exists():
            try:
                with conf_file.open('r') as conf_file_stream:
                    saml_test_config = json.load(conf_file_stream)
                self.login = RedactedValue(saml_test_config['login'])
                self.password = RedactedValue(saml_test_config['password'])
            except FileNotFoundError as e:
                pytest.fail(f"Unable to load SAML test config ({e})")
            except ValueError as e:
                pytest.fail(f"Unable to parse SAML test config credentials ({e})")
            except Exception as e:
                pytest.fail(f"Unexpected error while loading SAML test config ({e})")
        if 'WAZO_SAML_LOGIN' in os.environ:
            self.login = RedactedValue(os.environ['WAZO_SAML_LOGIN'])
        if 'WAZO_SAML_PASSWORD' in os.environ:
            self.password = RedactedValue(os.environ['WAZO_SAML_PASSWORD'])

        tenants = self.client.tenants.list(
            self.get_top_tenant()['uuid'], name='example'
        )
        if not tenants['items']:
            domain_name = 'example.com'
            self._setup_tenant_and_domain(domain_name)
            self._configure_saml(domain_name)
            self._create_user(self.login)
            self._reload_saml_config()
            self._accept_self_signed_certificate_on_stack()

    def _setup_tenant_and_domain(self, domain_name: str) -> None:
        self.tenant = self.client.tenants.new(
            name='example', slug='example', domain_names=[domain_name]
        )

    def _configure_saml(self, domain_name: str) -> None:
        acs_url_template: str = self.client.saml_config.get_acs_template()['acs_url']
        acs_url: str = acs_url_template.replace('{{STACK_URL}}', 'stack.wazo.local')
        domain_uuid: str = self.client.tenants.get_domains(self.tenant['uuid'])[
            'items'
        ][0]['uuid']
        with open('./assets/var/lib/wazo-auth/saml/saml.xml') as f:
            metadata: str = f.read()
            saml_config: dict[str, Any] = {
                'data': {
                    'acs_url': acs_url,
                    'entity_id': 'https://es.dev.wazo.io',
                    'domain_uuid': domain_uuid,
                },
                'files': {'metadata': metadata},
            }
            self.client.saml_config.create(self.tenant['uuid'], **saml_config)

    def _create_user(self, login: RedactedValue) -> None:
        user: dict[str, Any] = {
            'username': login._value,
            'firstname': 'saml',
            'lastname': 'test user',
            'password_hash': 'hash',  # NOSONAR
            'password_salt': 'salt',  # NOSONAR
            'purpose': 'user',
            'enabled': True,
            'tenant_uuid': self.tenant['uuid'],
            'authentication_method': 'saml',
        }
        UserDAO().create(**user)
        self.session.commit()

    def _accept_self_signed_certificate_on_stack(self) -> None:
        self.page.goto("https://stack.wazo.local/api/auth/0.1/tokens")

    def _reload_saml_config(self) -> None:
        self.restart_auth()

    def _click_login(self, page) -> None:
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

    def _login(self, page, login, password) -> None:
        page.get_by_placeholder("Email address, phone number").fill(login._value)
        page.get_by_role("button", name="Next").click()
        expect(page.get_by_role("heading"), "Failed to submit login").to_contain_text(
            "Enter password"
        )
        page.get_by_placeholder("Password").fill(password._value)
        page.get_by_role("button", name="Sign in").click()
        expect(
            page.get_by_role("heading"), "Failed to submit password"
        ).to_contain_text("Stay signed in?")
        page.get_by_role("button", name="No").click()

    def _renew_token(self, page) -> None:
        page.get_by_role("button", name="Renew token").click()

    def _logout(self, page) -> None:
        page.get_by_role("button", name="Logout").click()

    def _reuse_saml_session_id(self, page) -> None:
        page.get_by_role("button", name="Reuse SAML session ID").click()

    def _get_token_using_saml_session_id(self, page, saml_session_id) -> None:
        page.get_by_placeholder('Enter custom SAML session ID').fill(saml_session_id)
        page.get_by_role("button", name="Get token with custom SAML session ID").click()

    @pytest.mark.only_browser("chromium")
    @pytest.mark.browser_context_args(
        timezone_id="Europe/London", locale="en-GB", ignore_https_errors=True
    )
    def test_login_logout(self) -> None:
        self._click_login(self.page)
        self._login(self.page, self.login, self.password)
        expect(self.page.locator("h1"), "SSO handling failed").to_contain_text(
            "Wazo SAML Post ACS handling"
        )
        expect(
            self.page.locator("#token"), "Failed to retrieve token"
        ).not_to_contain_text("not yet known")
        expect(
            self.page.locator("#refresh"), "Failed to retrieve a refresh token"
        ).not_to_contain_text("not yet known")

        self._logout(self.page)
        expect(self.page).to_have_url(
            'https://app.wazo.local/postacs.html?logged_out=true', timeout=20000
        )
        expect(self.page.locator("#token")).to_contain_text("Failed")
        expect(self.page.locator("#refresh")).to_contain_text("Failed")

    @pytest.mark.only_browser("chromium")
    @pytest.mark.browser_context_args(
        timezone_id="Europe/London", locale="en-GB", ignore_https_errors=True
    )
    def test_logout_after_token_renewal(self) -> None:
        self._click_login(self.page)
        self._login(self.page, self.login, self.password)
        expect(self.page.locator("h1"), "SSO handling failed").to_contain_text(
            "Wazo SAML Post ACS handling"
        )
        expect(
            self.page.locator("#token"), "Failed to retrieve token"
        ).not_to_contain_text("not yet known")
        expect(
            self.page.locator("#refresh"), "Failed to retrieve a refresh token"
        ).not_to_contain_text("not yet known")

        self._renew_token(self.page)
        self._logout(self.page)
        expect(self.page).to_have_url(
            'https://app.wazo.local/postacs.html?logged_out=true', timeout=20000
        )
        expect(self.page.locator("#token")).to_contain_text("Failed")
        expect(self.page.locator("#refresh")).to_contain_text("Failed")

    @pytest.mark.only_browser("chromium")
    @pytest.mark.browser_context_args(
        timezone_id="Europe/London", locale="en-GB", ignore_https_errors=True
    )
    def test_reuse_saml_session(self) -> None:
        self._click_login(self.page)
        self._login(self.page, self.login, self.password)
        expect(self.page.locator("h1"), "SSO handling failed").to_contain_text(
            "Wazo SAML Post ACS handling"
        )
        expect(
            self.page.locator("#token"), "Failed to retrieve token"
        ).not_to_contain_text("not yet known")
        expect(
            self.page.locator("#refresh"), "Failed to retrieve a refresh token"
        ).not_to_contain_text("not yet known")

        self._reuse_saml_session_id(self.page)
        expect(self.page.locator("#token")).to_contain_text("Failed")
        expect(self.page.locator("#refresh")).to_contain_text("Failed")

    @pytest.mark.only_browser("chromium")
    @pytest.mark.browser_context_args(
        timezone_id="Europe/London", locale="en-GB", ignore_https_errors=True
    )
    def test_other_saml_session_ids(self) -> None:
        self._click_login(self.page)
        self._login(self.page, self.login, self.password)
        expect(self.page.locator("h1"), "SSO handling failed").to_contain_text(
            "Wazo SAML Post ACS handling"
        )
        expect(
            self.page.locator("#token"), "Failed to retrieve token"
        ).not_to_contain_text("not yet known")
        expect(
            self.page.locator("#refresh"), "Failed to retrieve a refresh token"
        ).not_to_contain_text("not yet known")

        self._get_token_using_saml_session_id(self.page, 'token-already-used')
        expect(self.page.locator("#custom_id_token")).to_contain_text("Failed")
