# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import uuid

import requests

from hamcrest import (
    assert_that,
    calling,
    contains,
    greater_than_or_equal_to,
    has_entries,
    has_items,
    has_length,
)

from xivo_test_helpers.hamcrest.raises import raises

from .helpers import base, fixtures

TENANT_UUID_1 = str(uuid.uuid4())
TENANT_UUID_2 = str(uuid.uuid4())


class TestUserSession(base.WazoAuthTestCase):

    @fixtures.http.user(username='username', password='pass')
    @fixtures.http.token(username='username', password='pass')
    @fixtures.http.token(username='username', password='pass', session_type='Mobile')
    def test_list(self, token_2, token_1, user):
        response = self.client.users.get_sessions(user['uuid'])
        assert_that(
            response,
            has_entries(
                items=has_items(
                    has_entries(uuid=token_2['session_uuid'], mobile=True),
                    has_entries(uuid=token_1['session_uuid'], mobile=False),
                )
            )
        )

    @fixtures.http.tenant(uuid=TENANT_UUID_1)
    @fixtures.http.tenant(uuid=TENANT_UUID_2)
    @fixtures.http.user(username='username', password='pass', tenant_uuid=TENANT_UUID_1)
    @fixtures.http.token(username='username', password='pass')
    def test_list_tenant_filtering(self, token, user, *_):
        # Different tenant
        assert_that(
            calling(self.client.users.get_sessions).with_args(user['uuid'], tenant_uuid=TENANT_UUID_2),
            raises(requests.HTTPError)
        )

        # Same tenant
        response = self.client.users.get_sessions(user['uuid'], tenant_uuid=TENANT_UUID_1)
        assert_that(
            response,
            has_entries(
                total=1,
                filtered=1,
                items=contains(has_entries(uuid=token['session_uuid']))
            )
        )

    @fixtures.http.user(username='username', password='pass')
    @fixtures.http.token(username='username', password='pass')
    @fixtures.http.token(username='username', password='pass')
    def test_list_paginating(self, token_2, token_1, user):
        response = self.client.users.get_sessions(user['uuid'], limit=1)
        assert_that(
            response,
            has_entries(
                total=greater_than_or_equal_to(2),
                filtered=greater_than_or_equal_to(2),
                items=has_length(1),
            )
        )

        response = self.client.users.get_sessions(user['uuid'], offset=1)
        assert_that(
            response,
            has_entries(
                total=greater_than_or_equal_to(2),
                filtered=greater_than_or_equal_to(2),
                items=has_length(response['total'] - 1)
            )
        )

    @fixtures.http.user(username='username', password='pass')
    @fixtures.http.token(username='username', password='pass')
    def test_delete(self, token, user):
        base.assert_no_error(self.client.users.remove_session, user['uuid'], token['session_uuid'])
        base.assert_no_error(self.client.users.remove_session, user['uuid'], token['session_uuid'])
