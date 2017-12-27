# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import requests
from hamcrest import assert_that, contains, equal_to, has_entries
from .helpers import fixtures
from .helpers.base import assert_http_error, assert_no_error, MockBackendTestCase, UNKNOWN_UUID


class TestEmailConfirmation(MockBackendTestCase):

    @fixtures.http_user_register(email_address='foobar@example.com')
    def test_email_confirmation(self, user):
        email_uuid = user['emails'][0]['uuid']

        assert_http_error(404, self.client.emails.confirm, UNKNOWN_UUID)
        assert_no_error(self.client.emails.confirm, email_uuid)

        updated_user = self.client.users.get(user['uuid'])
        assert_that(
            updated_user,
            has_entries(emails=contains(has_entries(
                address='foobar@example.com',
                confirmed=True))))

    @fixtures.http_user_register(email_address='foobar@example.com')
    def test_email_confirmation_get(self, user):
        email_uuid = user['emails'][0]['uuid']
        url = 'https://{}:{}/0.1/emails/{}/confirm'.format(self.get_host(), self._auth_port, email_uuid)
        token = self.client.token.new(backend='mock', expiration=3600)['token']
        response = requests.get(url, params={'token': token}, verify=False)
        assert_that(response.status_code, equal_to(200))

        updated_user = self.client.users.get(user['uuid'])
        assert_that(
            updated_user,
            has_entries(emails=contains(has_entries(
                address='foobar@example.com',
                confirmed=True))))
