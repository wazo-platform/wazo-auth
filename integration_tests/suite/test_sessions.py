# Copyright 2019-2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time
import uuid
from datetime import datetime, timezone

from hamcrest import (
    assert_that,
    contains_exactly,
    contains_string,
    empty,
    equal_to,
    greater_than_or_equal_to,
    has_entries,
    has_entry,
    has_item,
    has_items,
    has_key,
    has_length,
    is_not,
    none,
    not_,
)
from wazo_test_helpers import until

from wazo_auth.database.queries.token import TokenDAO

from .helpers import base, fixtures

TENANT_UUID_1 = str(uuid.uuid4())
TENANT_UUID_2 = str(uuid.uuid4())


@base.use_asset('base')
class TestSessions(base.APIIntegrationTest):
    def _create_generic_token(self, expiration: int) -> str:
        now = int(time.time())
        token_payload = {
            'auth_id': 'wazo-auth',
            'pbx_user_uuid': None,
            'xivo_uuid': None,
            'expire_t': now + expiration,
            'issued_t': now,
            'acl': [],
            'metadata': {},
            'user_agent': 'wazo-auth-agent',
            'remote_addr': '',
        }
        _, session_uuid = TokenDAO().create(token_payload, {})
        self.session.commit()  # force update in database
        return session_uuid

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
                total=1,
                filtered=1,
                items=contains_exactly(has_entries(uuid=session_1['uuid'])),
            ),
        )

        response = self.client.sessions.list(tenant_uuid=TENANT_UUID_2)
        assert_that(
            response,
            has_entries(
                total=1,
                filtered=1,
                items=contains_exactly(has_entries(uuid=session_2['uuid'])),
            ),
        )

    @fixtures.http.policy(acl=['auth.sessions.read'])
    @fixtures.http.user(username='session-metadata-user', password='pass')
    def test_list_token_metadata(self, policy, user):
        self.client.users.add_policy(user['uuid'], policy['uuid'])
        client = self.make_auth_client('session-metadata-user', 'pass')
        token = client.token.new(
            expiration=60,
            access_type='offline',
            client_id='my-client-id',
            user_agent='my-user-agent',
        )
        try:
            session = self._get_session(token['session_uuid'])

            assert_that(
                session,
                has_entries(
                    uuid=token['session_uuid'],
                    user_uuid=user['uuid'],
                    tenant_uuid=user['tenant_uuid'],
                    mobile=False,
                    user_agent='my-user-agent',
                    refresh_token_client_id='my-client-id',
                ),
            )
            assert_that(
                datetime.fromisoformat(session['created_at']),
                equal_to(self._utc_datetime(token['utc_issued_at'])),
            )
            assert_that(
                datetime.fromisoformat(session['expires_at']),
                equal_to(self._utc_datetime(token['utc_expires_at'])),
            )

            # the remote address is not exposed: behind a reverse proxy the
            # recorded value may be the proxy's
            assert_that(session, is_not(has_key('remote_addr')))

            # a session must never expose the token nor the refresh token
            assert_that(session, is_not(has_key('token')))
            assert_that(session, is_not(has_key('refresh_token')))
            assert_that(list(session.values()), is_not(has_item(token['token'])))
            assert_that(
                list(session.values()), is_not(has_item(token['refresh_token']))
            )
        finally:
            self.client.token.revoke(token['token'])

    @fixtures.http.user(username='online-session-user', password='pass')
    def test_list_token_metadata_without_refresh_token(self, user):
        client = self.make_auth_client('online-session-user', 'pass')
        token = client.token.new(expiration=60)
        try:
            session = self._get_session(token['session_uuid'])
            assert_that(session, has_entries(refresh_token_client_id=none()))
        finally:
            self.client.token.revoke(token['token'])

    @fixtures.http.session()
    def test_list_sorting_on_token_columns(self, session):
        for column in (
            'created_at',
            'expires_at',
            'user_agent',
            'refresh_token_client_id',
        ):
            for direction in ('asc', 'desc'):
                response = base.assert_no_error(
                    self.client.sessions.list, order=column, direction=direction
                )
                assert_that(response['items'], not_(empty()), column)

    def _get_session(self, session_uuid):
        sessions = self.client.sessions.list(recurse=True)['items']
        matching = [session for session in sessions if session['uuid'] == session_uuid]
        assert_that(matching, has_length(1), f'session {session_uuid} not found')
        return matching[0]

    @staticmethod
    def _utc_datetime(raw):
        # the token's issued_t/expire_t are truncated to the second in the database
        return datetime.fromisoformat(raw).replace(microsecond=0, tzinfo=timezone.utc)

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
        headers = {'name': 'auth_session_deleted'}
        msg_accumulator = self.bus.accumulator(headers=headers)

        self.client.sessions.delete(session['uuid'])

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(with_headers=True),
                has_items(
                    has_entries(
                        message=has_entries(
                            data={
                                'uuid': session['uuid'],
                                'user_uuid': session['user_uuid'],
                                'tenant_uuid': session['tenant_uuid'],
                            }
                        ),
                        headers=has_entry('tenant_uuid', session['tenant_uuid']),
                    )
                ),
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)

    @fixtures.http.user(username='foo')
    def test_create_event(self, user):
        headers = {'name': 'auth_session_created'}
        msg_accumulator = self.bus.accumulator(headers=headers)

        session_uuid = self._post_token('foo', user['password'], session_type='Mobile')[
            'session_uuid'
        ]

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(with_headers=True),
                contains_exactly(
                    has_entries(
                        message=has_entries(
                            data={
                                'uuid': session_uuid,
                                'user_uuid': user['uuid'],
                                'tenant_uuid': user['tenant_uuid'],
                                'mobile': True,
                            }
                        ),
                        headers=has_entry('tenant_uuid', user['tenant_uuid']),
                    )
                ),
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)

    @fixtures.http.user(username='foo')
    def test_expire_soon_event_when_token_is_about_to_expire(self, user):
        headers = {'name': 'auth_session_expire_soon'}
        msg_accumulator = self.bus.accumulator(headers=headers)
        session_uuid = self._post_token('foo', user['password'], expiration=3)[
            'session_uuid'
        ]

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(with_headers=True),
                has_items(
                    has_entries(
                        message=has_entries(
                            data={
                                'uuid': session_uuid,
                                'user_uuid': user['uuid'],
                                'tenant_uuid': user['tenant_uuid'],
                            }
                        ),
                        headers=has_entry('tenant_uuid', user['tenant_uuid']),
                    )
                ),
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)

    @fixtures.http.user(username='foo')
    def test_delete_event_when_token_expired(self, user):
        headers = {'name': 'auth_session_deleted'}
        msg_accumulator = self.bus.accumulator(headers=headers)

        session_uuid = self._post_token('foo', user['password'], expiration=1)[
            'session_uuid'
        ]

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(with_headers=True),
                has_items(
                    has_entries(
                        message=has_entries(
                            data={
                                'uuid': session_uuid,
                                'user_uuid': user['uuid'],
                                'tenant_uuid': user['tenant_uuid'],
                            }
                        ),
                        headers=has_entry('tenant_uuid', user['tenant_uuid']),
                    )
                ),
            )

        until.assert_(bus_received_msg, tries=10, interval=0.25)

    @fixtures.http.user(username='foo')
    def test_delete_event_when_token_deleted(self, user):
        headers = {'name': 'auth_session_deleted'}
        msg_accumulator = self.bus.accumulator(headers=headers)

        token = self._post_token('foo', user['password'])
        self.client.token.revoke(token['token'])

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(with_headers=True),
                has_items(
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

    def test_handle_generic_tokens_when_expired(self):
        assert self.client.config.get()['debug'] is True, 'debug must be set to true'

        test_start = time.time()
        session_uuid = self._create_generic_token(expiration=3)

        def assert_log_message():
            logs = self.service_logs(service_name='auth', since=test_start)
            assert_that(logs, contains_string(session_uuid))

        until.assert_(assert_log_message, tries=10, interval=0.5)

    @fixtures.http.user(username='foo')
    def test_that_delete_token_deletes_the_session(self, user):
        token = self._post_token('foo', user['password'])
        session_uuid = token['session_uuid']
        sessions = self.client.users.get_sessions(user['uuid'])
        assert_that(sessions['items'], contains_exactly(has_entries(uuid=session_uuid)))
        self.client.token.revoke(token['token'])
        sessions = self.client.users.get_sessions(user['uuid'])
        assert_that(sessions['items'], empty())
