# Copyright 2019-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import uuid

import requests
from hamcrest import (
    assert_that,
    calling,
    contains_exactly,
    greater_than_or_equal_to,
    has_entries,
    has_entry,
    has_item,
    has_items,
    has_length,
)
from wazo_test_helpers import until
from wazo_test_helpers.hamcrest.raises import raises

from .helpers import base, fixtures

TENANT_UUID_1 = str(uuid.uuid4())
TENANT_UUID_2 = str(uuid.uuid4())


@base.use_asset('base')
class TestUserSession(base.APIIntegrationTest):
    @fixtures.http.user(username='username', password='pass')
    @fixtures.http.token(username='username', password='pass')
    @fixtures.http.token(username='username', password='pass', session_type='Mobile')
    def test_list(self, user, token_1, token_2):
        response = self.client.users.get_sessions(user['uuid'])
        assert_that(
            response,
            has_entries(
                items=has_items(
                    has_entries(uuid=token_2['session_uuid'], mobile=True),
                    has_entries(uuid=token_1['session_uuid'], mobile=False),
                )
            ),
        )

    @fixtures.http.tenant(uuid=TENANT_UUID_1)
    @fixtures.http.tenant(uuid=TENANT_UUID_2)
    @fixtures.http.user(username='username', password='pass', tenant_uuid=TENANT_UUID_1)
    @fixtures.http.token(username='username', password='pass')
    def test_list_tenant_filtering(self, _, __, user, token):
        # Different tenant
        assert_that(
            calling(self.client.users.get_sessions).with_args(
                user['uuid'], tenant_uuid=TENANT_UUID_2
            ),
            raises(requests.HTTPError),
        )

        # Same tenant
        response = self.client.users.get_sessions(
            user['uuid'], tenant_uuid=TENANT_UUID_1
        )
        assert_that(
            response,
            has_entries(
                total=1,
                filtered=1,
                items=contains_exactly(has_entries(uuid=token['session_uuid'])),
            ),
        )

    @fixtures.http.user(username='username', password='pass')
    @fixtures.http.token(username='username', password='pass')
    @fixtures.http.token(username='username', password='pass')
    def test_list_paginating(self, user, token_1, token_2):
        response = self.client.users.get_sessions(user['uuid'], limit=1)
        assert_that(
            response,
            has_entries(
                total=greater_than_or_equal_to(2),
                filtered=greater_than_or_equal_to(2),
                items=has_length(1),
            ),
        )

        response = self.client.users.get_sessions(user['uuid'], offset=1)
        assert_that(
            response,
            has_entries(
                total=greater_than_or_equal_to(2),
                filtered=greater_than_or_equal_to(2),
                items=has_length(response['total'] - 1),
            ),
        )

    @fixtures.http.user(username='username', password='pass')
    @fixtures.http.token(username='username', password='pass')
    def test_delete(self, user, token):
        base.assert_no_error(
            self.client.users.remove_session, user['uuid'], token['session_uuid']
        )
        base.assert_no_error(
            self.client.users.remove_session, user['uuid'], token['session_uuid']
        )

    @fixtures.http.user(username='username', password='pass')
    @fixtures.http.token(username='username', password='pass')
    def test_delete_event(self, user, token):
        headers = {'name': 'auth_session_deleted'}
        msg_accumulator = self.bus.accumulator(headers=headers)

        self.client.users.remove_session(user['uuid'], token['session_uuid'])

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(with_headers=True),
                has_item(
                    has_entries(
                        message=has_entries(
                            data={
                                'uuid': token['session_uuid'],
                                'user_uuid': user['uuid'],
                                'tenant_uuid': user['tenant_uuid'],
                            }
                        ),
                        headers=has_entry('tenant_uuid', user['tenant_uuid']),
                    )
                ),
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)
