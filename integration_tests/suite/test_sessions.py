# Copyright 2019-2021 The Wazo Authors  (see the AUTHORS file)
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

from wazo_test_helpers import until
from .helpers import base, fixtures

TENANT_UUID_1 = str(uuid.uuid4())
TENANT_UUID_2 = str(uuid.uuid4())


@base.use_asset('base')
class TestSessions(base.APIIntegrationTest):
    @fixtures.http.session(mobile=False)
    @fixtures.http.session(mobile=True)
    def test_list(self, session_1, session_2):
        response = self.client.sessions.list()
        assert_that(
            response,
            has_entries(
                items=has_items(
                    has_entries(uuid=session_2['uuid'], mobile=True),
                    has_entries(uuid=session_1['uuid'], mobile=False),
                )
            ),
        )

    @fixtures.http.tenant(uuid=TENANT_UUID_1)
    @fixtures.http.tenant(uuid=TENANT_UUID_2)
    @fixtures.http.session(tenant_uuid=TENANT_UUID_1)
    @fixtures.http.session(tenant_uuid=TENANT_UUID_2)
    def test_list_tenant_filtering(self, _, __, session_1, session_2):
        # Different tenant
        response = self.client.sessions.list(tenant_uuid=self.top_tenant_uuid)
        assert_that(
            response,
            has_entries(
                items=not_(
                    has_items(
                        has_entries(uuid=session_2['uuid']),
                        has_entries(uuid=session_1['uuid']),
                    )
                )
            ),
        )

        # Different tenant with recurse
        response = self.client.sessions.list(
            tenant_uuid=self.top_tenant_uuid, recurse=True
        )
        assert_that(
            response,
            has_entries(
                items=has_items(
                    has_entries(uuid=session_1['uuid']),
                    has_entries(uuid=session_2['uuid']),
                )
            ),
        )

        # Same tenant
        response = self.client.sessions.list(tenant_uuid=TENANT_UUID_1)
        assert_that(
            response,
            has_entries(
                total=1, filtered=1, items=contains(has_entries(uuid=session_1['uuid']))
            ),
        )

        response = self.client.sessions.list(tenant_uuid=TENANT_UUID_2)
        assert_that(
            response,
            has_entries(
                total=1, filtered=1, items=contains(has_entries(uuid=session_2['uuid']))
            ),
        )

    @fixtures.http.session()
    @fixtures.http.session()
    def test_list_paginating(self, session_1, session_2):
        response = self.client.sessions.list(limit=1)
        assert_that(
            response,
            has_entries(
                total=greater_than_or_equal_to(2),
                filtered=greater_than_or_equal_to(2),
                items=has_length(1),
            ),
        )

        response = self.client.sessions.list(offset=1)
        assert_that(
            response,
            has_entries(
                total=greater_than_or_equal_to(2),
                filtered=greater_than_or_equal_to(2),
                items=has_length(response['total'] - 1),
            ),
        )

    @fixtures.http.session()
    def test_delete(self, session):
        with self.client_in_subtenant() as (client, _, sub_tenant):
            base.assert_no_error(client.sessions.delete, session['uuid'])
            base.assert_http_error(
                401,
                client.sessions.delete,
                session['uuid'],
                tenant_uuid=self.top_tenant_uuid,
            )

        self._assert_session_exists(session['uuid'])
        base.assert_no_error(self.client.sessions.delete, session['uuid'])
        base.assert_no_error(self.client.sessions.delete, session['uuid'])

    def _assert_session_exists(self, session_uuid):
        sessions = self.client.sessions.list()['items']
        assert_that(sessions, has_items(has_entries(uuid=session_uuid)))

    @fixtures.http.session()
    def test_delete_event(self, session):
        routing_key = 'auth.sessions.*.deleted'
        msg_accumulator = self.bus.accumulator(routing_key)

        self.client.sessions.delete(session['uuid'])

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(),
                has_items(
                    has_entries(
                        data={
                            'uuid': session['uuid'],
                            'user_uuid': session['user_uuid'],
                            'tenant_uuid': session['tenant_uuid'],
                        }
                    )
                ),
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)

    @fixtures.http.user(username='foo', password='bar')
    def test_create_event(self, user):
        routing_key = 'auth.sessions.*.created'
        msg_accumulator = self.bus.accumulator(routing_key)

        session_uuid = self._post_token('foo', 'bar', session_type='Mobile')[
            'session_uuid'
        ]

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(),
                contains(
                    has_entries(
                        data={
                            'uuid': session_uuid,
                            'user_uuid': user['uuid'],
                            'tenant_uuid': user['tenant_uuid'],
                            'mobile': True,
                        }
                    )
                ),
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)

    @fixtures.http.user(username='foo', password='bar')
    def test_expire_soon_event_when_token_is_about_to_expire(self, user):
        routing_key = 'auth.users.{uuid}.sessions.*.expire_soon'.format(
            uuid=user['uuid']
        )
        msg_accumulator = self.bus.accumulator(routing_key)

        session_uuid = self._post_token('foo', 'bar', expiration=3)['session_uuid']

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(),
                has_items(
                    has_entries(
                        data={
                            'uuid': session_uuid,
                            'user_uuid': user['uuid'],
                            'tenant_uuid': user['tenant_uuid'],
                        }
                    )
                ),
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)

    @fixtures.http.user(username='foo', password='bar')
    def test_delete_event_when_token_expired(self, user):
        routing_key = 'auth.sessions.*.deleted'
        msg_accumulator = self.bus.accumulator(routing_key)

        session_uuid = self._post_token('foo', 'bar', expiration=1)['session_uuid']

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(),
                has_items(
                    has_entries(
                        data={
                            'uuid': session_uuid,
                            'user_uuid': user['uuid'],
                            'tenant_uuid': user['tenant_uuid'],
                        }
                    )
                ),
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)

    @fixtures.http.user(username='foo', password='bar')
    def test_delete_event_when_token_deleted(self, user):
        routing_key = 'auth.sessions.*.deleted'
        msg_accumulator = self.bus.accumulator(routing_key)

        token = self._post_token('foo', 'bar')
        self.client.token.revoke(token['token'])

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(),
                has_items(
                    has_entries(
                        data={
                            'uuid': token['session_uuid'],
                            'user_uuid': user['uuid'],
                            'tenant_uuid': user['tenant_uuid'],
                        }
                    )
                ),
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)
