# Copyright 2018-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
import yaml
from hamcrest import (
    assert_that,
    contains_inanyorder,
    contains_string,
    has_entries,
    has_items,
    not_,
)

from .helpers import fixtures, base
from .helpers.base import assert_http_error, assert_no_error


@base.use_asset('base')
class TestResetPassword(base.APIIntegrationTest):
    @fixtures.http.user(username='foo', email_address='foo@example.com')
    @fixtures.http.user(username='bar', email_address='bar@example.com')
    def test_password_reset(self, foo, bar):
        self.clean_emails()
        self.client.users.reset_password(username='foo')
        self.client.users.reset_password(email='bar@example.com')

        emails = self.get_emails()

        assert_that(
            emails,
            contains_inanyorder(
                contains_string('username: foo'), contains_string('username: bar')
            ),
        )

        new_password = '5ecr37'
        for email in emails:
            self._update_password_from_email(email, new_password)

        for username in ('foo', 'bar'):
            user_client = self.make_auth_client(username, new_password)
            assert_no_error(user_client.token.new, 'wazo_user', expiration=1)

    def _update_password_from_email(self, raw_email, password):
        headers, body = raw_email.split('\n\n', 1)
        email_fields = yaml.safe_load(body)

        token = email_fields['token']
        user_uuid = email_fields['user_uuid']

        return self.client.users.set_password(user_uuid, password, token)

    @fixtures.http.user()
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

    @fixtures.http.user()
    def test_set_password_does_not_log_password(self, user):
        new_password = '5ecr37'

        time_start = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        self.client.users.set_password(user['uuid'], new_password)

        logs = self.service_logs('auth', since=time_start)
        assert_that(logs, not_(contains_string(new_password)))

    @fixtures.http.user(username='foo', email_address='foo@example.com')
    def test_password_reset_do_not_create_session_with_invalid_user_uuid(self, foo):
        self.client.users.reset_password(username='foo')

        response = self.client.sessions.list()
        assert_that(response['items'], has_items(has_entries(user_uuid=None)))
