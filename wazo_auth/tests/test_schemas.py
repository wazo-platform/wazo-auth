# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime, timezone
from unittest import TestCase

from hamcrest import (
    assert_that,
    contains_exactly,
    has_entries,
    has_item,
    has_key,
    none,
    not_,
)

from wazo_auth.schemas import SessionSchema


class TestSessionSchema(TestCase):
    def setUp(self):
        self.schema = SessionSchema()
        # as returned by SessionDAO.list_()
        self.session = {
            'uuid': '6a2b7c5e-5f27-4f5e-9d6c-2f0a9b8c7d61',
            'tenant_uuid': '007ca8d5-d361-42de-a0ed-8680105596b0',
            'user_uuid': 'a014e8f7-f305-492a-9350-51f149ca8f27',
            'mobile': True,
            'user_agent': 'wazo-shift/2.4.1 (Android 14)',
            'remote_addr': '203.0.113.7',
            'acl': ['auth.sessions.read', 'confd.#'],
            'issued_at': datetime(2026, 9, 15, 8, 12, 44, tzinfo=timezone.utc),
            'expires_at': datetime(2026, 9, 15, 10, 12, 44, tzinfo=timezone.utc),
            'client_id': 'wazo-shift-android',
        }

    def test_that_the_token_metadata_is_exposed(self):
        result = self.schema.dump(self.session)

        assert_that(
            result,
            has_entries(
                uuid='6a2b7c5e-5f27-4f5e-9d6c-2f0a9b8c7d61',
                tenant_uuid='007ca8d5-d361-42de-a0ed-8680105596b0',
                user_uuid='a014e8f7-f305-492a-9350-51f149ca8f27',
                mobile=True,
                user_agent='wazo-shift/2.4.1 (Android 14)',
                acl=contains_exactly('auth.sessions.read', 'confd.#'),
                client_id='wazo-shift-android',
            ),
        )

    def test_that_the_remote_addr_is_not_exposed(self):
        # behind a reverse proxy the recorded address may be the proxy's, so
        # the value is not exposed until it can be trusted
        result = self.schema.dump(self.session)

        assert_that(result, not_(has_key('remote_addr')))

    def test_that_the_timestamps_are_dumped_in_utc(self):
        result = self.schema.dump(self.session)

        assert_that(
            result,
            has_entries(
                issued_at='2026-09-15T08:12:44+00:00',
                expires_at='2026-09-15T10:12:44+00:00',
            ),
        )

    def test_that_a_session_without_a_refresh_token_has_no_client_id(self):
        result = self.schema.dump({**self.session, 'client_id': None})

        assert_that(result, has_entries(client_id=none()))

    def test_that_the_token_is_not_exposed(self):
        # a session is a proxy for its token: neither the token, the refresh
        # token (the bearer secret) nor the token metadata may leak
        session = {
            **self.session,
            'token_uuid': 'the-token',
            'refresh_token_uuid': 'the-secret-refresh-token',
            'metadata': {'pbx_user_uuid': 'a-pbx-user-uuid'},
        }

        result = self.schema.dump(session)

        assert_that(result, not_(has_key('token_uuid')))
        assert_that(result, not_(has_key('refresh_token_uuid')))
        assert_that(result, not_(has_key('metadata')))
        assert_that(list(result.values()), not_(has_item('the-token')))
        assert_that(list(result.values()), not_(has_item('the-secret-refresh-token')))
