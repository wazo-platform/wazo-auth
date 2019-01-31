# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import (
    assert_that,
    contains_inanyorder,
    empty,
    has_entries
)
from xivo_test_helpers.hamcrest.uuid_ import uuid_
from .helpers import fixtures
from .helpers.base import (
    assert_http_error,
    WazoAuthTestCase,
    UNKNOWN_UUID,
)

ONE = {'address': 'one@example.com', 'main': True, 'confirmed': True}
TWO = {'address': 'two@example.com', 'main': False, 'confirmed': False}
THREE = {'address': 'three@example.com', 'main': False, 'confirmed': True}


class TestEmails(WazoAuthTestCase):

    @fixtures.http_user(username='foobar')
    def test_email_updates_as_admin(self, foobar):
        assert_http_error(404, self.client.admin.update_user_emails, UNKNOWN_UUID, [])
        assert_http_error(
            400,
            self.client.users.update_emails,
            foobar['uuid'], [ONE, ONE],
        )

        result = self.client.admin.update_user_emails(foobar['uuid'], [ONE, TWO])
        assert_that(
            result,
            contains_inanyorder(
                has_entries(uuid=uuid_(), **ONE),
                has_entries(uuid=uuid_(), **TWO),
            )
        )

        one_uuid = [entry['uuid'] for entry in result if entry['address'] == 'one@example.com'][0]
        result = self.client.admin.update_user_emails(foobar['uuid'], [ONE, THREE])
        assert_that(
            result,
            contains_inanyorder(
                has_entries(uuid=one_uuid, **ONE),
                has_entries(uuid=uuid_(), **THREE),
            )
        )

    @fixtures.http_user(username='foobar', email_address='one@example.com')
    def test_email_updates_as_user(self, foobar):
        assert_http_error(404, self.client.users.update_emails, UNKNOWN_UUID, [])
        assert_http_error(
            400,
            self.client.users.update_emails,
            foobar['uuid'], [ONE, ONE]
        )

        email_uuid = foobar['emails'][0]['uuid']
        result = self.client.users.update_emails(foobar['uuid'], [ONE, THREE])
        assert_that(
            result,
            contains_inanyorder(
                has_entries(uuid=email_uuid, **ONE),
                has_entries(uuid=uuid_(), address=THREE['address'], main=THREE['main'], confirmed=False),
                # Confirmed is ignored when modifying as a user                                   ^^^^^
            )
        )

        result = self.client.users.update_emails(foobar['uuid'], [])
        assert_that(result, empty())

    @fixtures.http_user(username='bar', email_address='bar@example.com')
    @fixtures.http_user(username='foo', email_address='foo@example.com')
    def test_duplicate_email(self, foo, bar):
        duplicated_emails = [
            {'address': 'bar@example.com', 'main': True, 'confirmed': True},
        ]
        assert_http_error(409, self.client.users.update_emails, foo['uuid'], duplicated_emails)
