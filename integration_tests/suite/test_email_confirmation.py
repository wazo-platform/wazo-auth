# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import assert_that, contains, has_entries
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
