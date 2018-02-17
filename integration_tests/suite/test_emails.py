# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import (
    assert_that,
    contains_inanyorder,
    has_entries
)
from xivo_test_helpers.hamcrest.uuid_ import uuid_
from .helpers import fixtures
from .helpers.base import (
    assert_http_error,
    MockBackendTestCase,
    UNKNOWN_UUID,
)

ONE = dict(address='one@example.com', main=True, confirmed=True)
TWO = dict(address='two@example.com', main=False, confirmed=False)
THREE = dict(address='three@example.com', main=False, confirmed=True)


class TestEmails(MockBackendTestCase):

    @fixtures.http_user(username='foobar')
    def test_email_updates_admin(self, foobar):
        assert_http_error(404, self.client.users.update_emails, UNKNOWN_UUID, [], admin=True)
        assert_http_error(
            400,
            self.client.users.update_emails,
            foobar['uuid'], [ONE, ONE], admin=True,
        )

        result = self.client.users.update_emails(foobar['uuid'], [ONE, TWO], admin=True)
        assert_that(
            result,
            contains_inanyorder(
                has_entries(uuid=uuid_(), **ONE),
                has_entries(uuid=uuid_(), **TWO),
            )
        )

        one_uuid = [entry['uuid'] for entry in result if entry['address'] == 'one@example.com'][0]
        result = self.client.users.update_emails(foobar['uuid'], [ONE, THREE], admin=True)
        assert_that(
            result,
            contains_inanyorder(
                has_entries(uuid=one_uuid, **ONE),
                has_entries(uuid=uuid_(), **THREE),
            )
        )
