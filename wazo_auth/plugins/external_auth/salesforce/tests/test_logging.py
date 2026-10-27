# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

import requests
from hamcrest import assert_that, empty, equal_to, has_item, is_, not_

from .helpers import (
    ACCESS_TOKEN,
    CLIENT_SECRET,
    CODE,
    NEW_ACCESS_TOKEN,
    REFRESH_TOKEN,
    FakeTokenEndpoint,
    salesforce_token_body,
)
from .test_http import NOW, TENANT_UUID, USER_UUID, SalesforceResourceTestCase

SECRETS = (ACCESS_TOKEN, NEW_ACCESS_TOKEN, REFRESH_TOKEN, CODE, CLIENT_SECRET)
PLUGIN_LOGGER = 'wazo_auth.plugins.external_auth.salesforce'


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.lines = []
        self.formatter = logging.Formatter('%(name)s %(levelname)s %(message)s')

    def emit(self, record):
        self.lines.append((record.name, record.levelno, self.format(record)))


class TestNoSecretInTheLogs(SalesforceResourceTestCase):
    def setUp(self):
        super().setUp()
        root = logging.getLogger()
        self.capture = _Capture()
        root.addHandler(self.capture)
        self.addCleanup(root.removeHandler, self.capture)
        previous_level = root.level
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.setLevel, previous_level)

    def test_create_then_refresh_logs_no_secret(self):
        self.post({})
        on_code = self.mocks['RelayListener'].call_args.args[2]
        with FakeTokenEndpoint((200, salesforce_token_body())).serving():
            on_code(CODE)
        link = self.external_auth_service.create.call_args.args[2]
        self.stored(**dict(link, token_expiration=NOW - 1))
        refresh = (200, salesforce_token_body(access_token=NEW_ACCESS_TOKEN))
        with FakeTokenEndpoint(refresh).serving():
            assert_that(self.get().status_code, equal_to(200))
        with FakeTokenEndpoint((400, {'error': 'invalid_grant'})).serving():
            assert_that(self.get().status_code, equal_to(502))
        with FakeTokenEndpoint(requests.ConnectionError(ACCESS_TOKEN)).serving():
            assert_that(self.get().status_code, equal_to(502))

        self.assert_no_secret_logged()

    def test_a_refused_code_logs_no_secret(self):
        self.post({})
        on_code = self.mocks['RelayListener'].call_args.args[2]
        with FakeTokenEndpoint((400, {'error': 'invalid_grant'})).serving():
            on_code(CODE)

        self.assert_no_secret_logged()

    def assert_no_secret_logged(self):
        plugin_lines = [
            line
            for name, _, line in self.capture.lines
            if name.startswith(PLUGIN_LOGGER)
        ]
        info_lines = [
            line for _, level, line in self.capture.lines if level >= logging.INFO
        ]
        assert_that(plugin_lines, not_(empty()))
        # the plugin says who and what happened, never the token
        assert_that(
            [
                line
                for line in plugin_lines
                if USER_UUID in line and TENANT_UUID in line
            ],
            not_(empty()),
        )
        for secret in SECRETS:
            assert_that(
                [line for line in plugin_lines if secret in line], is_(empty()), secret
            )
            assert_that(
                [line for line in info_lines if secret in line], is_(empty()), secret
            )

    def test_the_capture_sees_the_library_debug_lines(self):
        self.stored(
            access_token=ACCESS_TOKEN,
            refresh_token=REFRESH_TOKEN,
            token_expiration=NOW - 1,
        )
        refresh = (200, salesforce_token_body(access_token=NEW_ACCESS_TOKEN))
        with FakeTokenEndpoint(refresh).serving():
            self.get()

        names = [
            name for name, level, _ in self.capture.lines if level == logging.DEBUG
        ]
        assert_that(names, has_item('requests_oauthlib.oauth2_session'))
