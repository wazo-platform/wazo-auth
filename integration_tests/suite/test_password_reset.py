# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import yaml
from hamcrest import assert_that, contains_inanyorder, contains_string

from .helpers import fixtures
from .helpers.base import (
    assert_http_error,
    assert_no_error,
    WazoAuthTestCase,
)


class TestResetPassword(WazoAuthTestCase):

    @fixtures.http_user(username='foo', email_address='foo@example.com')
    @fixtures.http_user(username='bar', email_address='bar@example.com')
    def test_password_reset(self, bar, foo):
        self.client.users.reset_password(username='foo')
        self.client.users.reset_password(email='bar@example.com')

        emails = self.get_emails()

        assert_that(emails, contains_inanyorder(
            contains_string('username: foo'),
            contains_string('username: bar')))

        new_password = '5ecr37'
        for email in emails:
            self._update_password_from_email(email, new_password)

        for username in ('foo', 'bar'):
            user_client = self.new_auth_client(username, new_password)
            assert_no_error(user_client.token.new, 'wazo_user', expiration=1)

    def _update_password_from_email(self, raw_email, password):
        headers, body = raw_email.split('\n\n', 1)
        email_fields = yaml.load(body)

        token = email_fields['token']
        user_uuid = email_fields['user_uuid']

        return self.client.users.set_password(user_uuid, password, token)

    @fixtures.http_user()
    def test_set_password(self, user):
        new_password = '5ecr37'

        self.client.users.set_password(user['uuid'], new_password)

        user_client = self.new_auth_client(user['username'], new_password)
        assert_no_error(user_client.token.new, 'wazo_user', expiration=1)

        new_password = None

        self.client.users.set_password(user['uuid'], new_password)

        user_client = self.new_auth_client(user['username'], new_password)
        assert_http_error(401, user_client.token.new, 'wazo_user', expiration=1)
