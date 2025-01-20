# Copyright 2018-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time

import yaml
from hamcrest import (
    assert_that,
    contains_inanyorder,
    contains_string,
    has_entries,
    has_items,
    matches_regexp,
    not_,
)

from .helpers import base, fixtures
from .helpers.base import assert_http_error, assert_no_error


@base.use_asset('base')
class TestResetPassword(base.APIIntegrationTest):
    @fixtures.http.user(username='foo', email_address='foo@example.com')
    @fixtures.http.user(username='bar', email_address='bar@example.com')
    @fixtures.http.user(username=None, email_address='u3@example.com')
    @fixtures.http.user(username='u4@example.com', email_address='other@example.com')
    def test_password_reset(self, foo, bar, u3, u4):
        self.clean_emails()
        self.client.users.reset_password(username='foo')
        self.client.users.reset_password(email='bar@example.com')
        self.client.users.reset_password(login='u3@example.com')
        self.client.users.reset_password(login='u4@example.com')

        emails = self.get_emails()

        assert_that(
            emails,
            contains_inanyorder(
                contains_string('username: foo'),
                contains_string('username: bar'),
                contains_string('username: None'),
                contains_string('username: u4@example.com'),
            ),
        )

        self.assert_last_email(
            from_name='password_reset_from_name_sentinel',
            from_address='password_reset_from_address_sentinel@example.com',
            to_name=f'''"{u4['username']}"''',
            to_address='other@example.com',
        )

        new_password = '5ecr37'
        for email in emails:
            self._update_password_from_email(email, new_password)

        for username in ('foo', 'bar', 'u3@example.com', 'u4@example.com'):
            user_client = self.make_auth_client(username, new_password)
            assert_no_error(user_client.token.new, 'wazo_user', expiration=1)

    def _update_password_from_email(self, raw_email, password):
        headers, body = raw_email.split('\n\n', 1)
        email_fields = yaml.safe_load(body)

        token = email_fields['token']
        user_uuid = email_fields['user_uuid']

        return self.client.users.set_password(user_uuid, password, token)

    @fixtures.http.user(username='foobar')
    def test_set_password(self, user):
        new_password = '5ecr37'

        self.client.users.set_password(user['uuid'], new_password)

        user_client = self.make_auth_client(user['username'], new_password)
        assert_no_error(user_client.token.new, 'wazo_user', expiration=1)

        new_password = None

        self.client.users.set_password(user['uuid'], new_password)

        user_client = self.make_auth_client(user['username'], new_password)
        assert_http_error(401, user_client.token.new, 'wazo_user', expiration=1)

        # non-regression: bootstrap user still have password
        assert_no_error(self.client.token.new, 'wazo_user', expiration=1)

    @fixtures.http.user(username='foobar')
    def test_set_password_does_not_log_password(self, user):
        new_password = '5ecr37'

        with self.asset_cls.capture_logs(service_name='auth') as logs:
            self.client.users.set_password(user['uuid'], new_password)

        assert_that(logs.result(), not_(contains_string(new_password)))

    @fixtures.http.user(username='foo', email_address='foo@example.com')
    def test_password_reset_do_not_create_session_with_invalid_user_uuid(self, foo):
        self.client.users.reset_password(username='foo')

        response = self.client.sessions.list()
        assert_that(response['items'], has_items(has_entries(user_uuid=None)))

    @fixtures.http.user(username='bob', email_address='user@example.com')
    def test_password_reset_from_custom_plugin(self, user):
        config = {'email_notification_plugin': 'logger'}
        with self.auth_with_config(config):
            test_start = time.time()
            self.client.users.reset_password(username='bob')

            logs = self.service_logs(service_name='auth', since=test_start)
            context_str = "'username': 'bob'"
            regex = f"email_notification_logger,send_password_reset,.*{context_str}"
            assert_that(logs, matches_regexp(regex))
