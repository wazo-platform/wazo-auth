# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import uuid

from hamcrest import (
    assert_that,
    contains,
    greater_than_or_equal_to,
    has_entries,
    has_items,
    has_length,
    not_,
)

from xivo_test_helpers import until
from .helpers import base, fixtures

TENANT_UUID_1 = str(uuid.uuid4())
TENANT_UUID_2 = str(uuid.uuid4())


class TestSessions(base.WazoAuthTestCase):

    @fixtures.http.user(username='one', password='pass')
    @fixtures.http.user(username='two', password='pass')
    @fixtures.http.token(username='one', password='pass')
    @fixtures.http.token(username='two', password='pass', session_type='Mobile')
    def test_list(self, token_2, token_1, *_):
        response = self.client.sessions.list()
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
    @fixtures.http.user(username='one', password='pass', tenant_uuid=TENANT_UUID_1)
    @fixtures.http.user(username='two', password='pass', tenant_uuid=TENANT_UUID_2)
    @fixtures.http.token(username='one', password='pass')
    @fixtures.http.token(username='two', password='pass')
    def test_list_tenant_filtering(self, token_2, token_1, *_):
        # Different tenant
        response = self.client.sessions.list(tenant_uuid=self.top_tenant_uuid)
        assert_that(
            response,
            has_entries(
                items=not_(has_items(
                    has_entries(uuid=token_2['session_uuid']),
                    has_entries(uuid=token_1['session_uuid']),
                ))
            )
        )

        # Different tenant with recurse
        response = self.client.sessions.list(tenant_uuid=self.top_tenant_uuid, recurse=True)
        assert_that(
            response,
            has_entries(
                items=has_items(
                    has_entries(uuid=token_1['session_uuid']),
                    has_entries(uuid=token_2['session_uuid']),
                )
            )
        )

        # Same tenant
        response = self.client.sessions.list(tenant_uuid=TENANT_UUID_1)
        assert_that(
            response,
            has_entries(
                total=1,
                filtered=1,
                items=contains(has_entries(uuid=token_1['session_uuid']))
            )
        )

        response = self.client.sessions.list(tenant_uuid=TENANT_UUID_2)
        assert_that(
            response,
            has_entries(
                total=1,
                filtered=1,
                items=contains(has_entries(uuid=token_2['session_uuid']))
            )
        )

    @fixtures.http.user(username='one', password='pass')
    @fixtures.http.user(username='two', password='pass')
    @fixtures.http.token(username='one', password='pass')
    @fixtures.http.token(username='two', password='pass')
    def test_list_paginating(self, token_2, token_1, *_):
        response = self.client.sessions.list(limit=1)
        assert_that(
            response,
            has_entries(
                total=greater_than_or_equal_to(2),
                filtered=greater_than_or_equal_to(2),
                items=has_length(1),
            )
        )

        response = self.client.sessions.list(offset=1)
        assert_that(
            response,
            has_entries(
                total=greater_than_or_equal_to(2),
                filtered=greater_than_or_equal_to(2),
                items=has_length(response['total'] - 1)
            )
        )

    @fixtures.http.user(username='foo', password='bar')
    def test_create_event(self, user):
        routing_key = 'auth.sessions.*.created'
        msg_accumulator = self.new_message_accumulator(routing_key)

        session_uuid = self._post_token('foo', 'bar', session_type='Mobile')['session_uuid']

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(),
                contains(has_entries(
                    data={
                        'uuid': session_uuid,
                        'user_uuid': user['uuid'],
                        'tenant_uuid': user['tenant_uuid'],
                        'mobile': True,
                    }
                ))
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)

    @fixtures.http.user(username='foo', password='bar')
    def test_delete_event(self, user):
        routing_key = 'auth.sessions.*.deleted'
        msg_accumulator = self.new_message_accumulator(routing_key)

        session_uuid = self._post_token('foo', 'bar', expiration=1)['session_uuid']

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(),
                contains(has_entries(
                    data={
                        'uuid': session_uuid,
                        'user_uuid': user['uuid'],
                        'tenant_uuid': user['tenant_uuid'],
                    }
                ))
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)
