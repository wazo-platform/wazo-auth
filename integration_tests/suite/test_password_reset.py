# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import yaml
from hamcrest import assert_that, contains_inanyorder, contains_string

from .helpers import fixtures
from .helpers.base import assert_no_error, MockBackendTestCase


class TestResetPassword(MockBackendTestCase):

    email_dir = '/var/mail'

    @fixtures.http_user(username='foo', email_address='foo@example.com')
    @fixtures.http_user(username='bar', email_address='bar@example.com')
    def test_password_reset(self, bar, foo):
        self.client.users.reset_password(username='foo')
        self.client.users.reset_password(email='bar@example.com')

        emails = self._get_emails()

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

    def _get_emails(self):
        return [self._email_body(f) for f in self._get_email_filenames()]

    def _email_body(self, filename):
        return self.docker_exec(['cat', '{}/{}'.format(self.email_dir, filename)], 'smtp')

    def _get_email_filenames(self):
        return self.docker_exec(['ls', self.email_dir], 'smtp').strip().split('\n')
