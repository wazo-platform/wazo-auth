# Copyright 2019-2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time
import uuid
from datetime import datetime, timezone

from hamcrest import (
    assert_that,
    contains_exactly,
    contains_inanyorder,
    empty,
    equal_to,
    has_entries,
    has_items,
    has_properties,
    none,
)

from wazo_auth.database import models

from .helpers import base, fixtures

TENANT_UUID_1 = str(uuid.uuid4())
TENANT_UUID_2 = str(uuid.uuid4())
TENANT_UUID_3 = str(uuid.uuid4())
SESSION_UUID_1 = str(uuid.uuid4())
SESSION_UUID_2 = str(uuid.uuid4())


def new_token_body(**kwargs):
    now = int(time.time())
    body = {
        'auth_id': str(uuid.uuid4()),
        'pbx_user_uuid': str(uuid.uuid4()),
        'xivo_uuid': str(uuid.uuid4()),
        'issued_t': now,
        'expire_t': now + 120,
        'acl': [],
        'metadata': {},
        'user_agent': '',
        'remote_addr': '',
    }
    body.update(kwargs)
    return body


@base.use_asset('database')
class TestSessionDAO(base.DAOTestCase):
    @fixtures.db.tenant(uuid=TENANT_UUID_1)
    @fixtures.db.token(session={'tenant_uuid': TENANT_UUID_1, 'mobile': True})
    @fixtures.db.token(session={'mobile': False})
    def test_list(self, tenant_uuid, token_1, token_2):
        result = self._session_dao.list_()
        assert_that(
            result,
            contains_inanyorder(
                has_entries(
                    uuid=token_1['session_uuid'],
                    user_uuid=token_1['auth_id'],
                    tenant_uuid=tenant_uuid,
                ),
                has_entries(uuid=token_2['session_uuid'], user_uuid=token_2['auth_id']),
            ),
        )

        result = self._session_dao.list_(tenant_uuids=[TENANT_UUID_1])
        assert_that(
            result, contains_inanyorder(has_entries(uuid=token_1['session_uuid']))
        )

        result = self._session_dao.list_(tenant_uuids=[])
        assert_that(result, empty())

        result = self._session_dao.list_(order='mobile', direction='desc')
        assert_that(
            result,
            contains_exactly(
                has_entries(uuid=token_1['session_uuid']),
                has_entries(uuid=token_2['session_uuid']),
            ),
        )

        result = self._session_dao.list_(order='mobile', direction='asc', limit=1)
        assert_that(result, contains_exactly(has_entries(uuid=token_2['session_uuid'])))

        result = self._session_dao.list_(order='mobile', direction='asc', offset=1)
        assert_that(result, contains_exactly(has_entries(uuid=token_1['session_uuid'])))

        result = self._session_dao.list_(user_uuid=token_1['auth_id'])
        assert_that(result, contains_exactly(has_entries(uuid=token_1['session_uuid'])))

    @fixtures.db.token(auth_id='', session_uuid=SESSION_UUID_1)
    @fixtures.db.token(auth_id='not-uuid-id', session_uuid=SESSION_UUID_1)
    def test_list_whith_no_uuid_auth_id(self, token_1, token_2):
        session_uuid = token_1['session_uuid']
        result = self._session_dao.list_()
        assert_that(result, has_items(has_entries(uuid=session_uuid, user_uuid=None)))

        session_uuid = token_2['session_uuid']
        result = self._session_dao.list_()
        assert_that(result, has_items(has_entries(uuid=session_uuid, user_uuid=None)))

    @fixtures.db.tenant(uuid=TENANT_UUID_1)
    @fixtures.db.token(session_uuid=SESSION_UUID_2)
    @fixtures.db.token(session={'tenant_uuid': TENANT_UUID_1})
    def test_count(self, *_):
        result = self._session_dao.count()
        assert_that(result, equal_to(2))

        result = self._session_dao.count(tenant_uuids=[TENANT_UUID_1])
        assert_that(result, equal_to(1))

        result = self._session_dao.count(tenant_uuids=[])
        assert_that(result, equal_to(0))

    @fixtures.db.tenant(uuid=TENANT_UUID_1)
    @fixtures.db.token(session={'tenant_uuid': TENANT_UUID_1})
    @fixtures.db.token()
    def test_count_by_user(self, tenant_uuid, token_1, token_2):
        result = self._session_dao.count(user_uuid=token_1['auth_id'])
        assert_that(result, equal_to(1))

        result = self._session_dao.count(user_uuid=self.unknown_uuid)
        assert_that(result, equal_to(0))

    @fixtures.db.refresh_token()
    @fixtures.db.token()
    def test_delete_by_refresh_token_uuid(self, refresh_token_uuid, unrelated_token):
        now = int(time.time())
        token_a_body = {
            'auth_id': 'auth-a',
            'pbx_user_uuid': str(uuid.uuid4()),
            'xivo_uuid': str(uuid.uuid4()),
            'issued_t': now,
            'expire_t': now + 120,
            'acl': [],
            'metadata': {},
            'user_agent': '',
            'remote_addr': '',
        }
        token_b_body = {**token_a_body, 'auth_id': 'auth-b'}
        _, session_a_uuid = self._token_dao.create(
            token_a_body, {}, refresh_token_uuid=refresh_token_uuid
        )
        _, session_b_uuid = self._token_dao.create(
            token_b_body, {}, refresh_token_uuid=refresh_token_uuid
        )

        deleted = self._session_dao.delete_by_refresh_token_uuid(refresh_token_uuid)

        assert_that(deleted, contains_inanyorder(session_a_uuid, session_b_uuid))

        remaining_tokens = self.session.query(models.Token).all()
        assert_that(
            remaining_tokens,
            contains_exactly(has_properties(uuid=unrelated_token['uuid'])),
        )
        remaining_sessions = self.session.query(models.Session).all()
        assert_that(
            remaining_sessions,
            contains_exactly(
                has_properties(uuid=unrelated_token['session_uuid']),
            ),
        )

    @fixtures.db.refresh_token()
    def test_delete_by_refresh_token_uuid_when_no_sessions(self, refresh_token_uuid):
        deleted = self._session_dao.delete_by_refresh_token_uuid(refresh_token_uuid)

        assert_that(deleted, empty())

    @fixtures.db.tenant(uuid=TENANT_UUID_1)
    @fixtures.db.refresh_token(client_id='my-client-id')
    def test_list_token_metadata(self, tenant_uuid, refresh_token_uuid):
        now = int(time.time())
        token_body = new_token_body(
            issued_t=now,
            expire_t=now + 120,
            acl=['auth.#', 'confd.#'],
            user_agent='my-user-agent',
        )
        _, session_uuid = self._token_dao.create(
            token_body,
            {'tenant_uuid': TENANT_UUID_1},
            refresh_token_uuid=refresh_token_uuid,
        )

        result = self._session_dao.list_(tenant_uuids=[TENANT_UUID_1])
        assert_that(
            result,
            contains_exactly(
                has_entries(
                    uuid=session_uuid,
                    tenant_uuid=TENANT_UUID_1,
                    user_uuid=token_body['auth_id'],
                    mobile=False,
                    user_agent='my-user-agent',
                    refresh_token_client_id='my-client-id',
                    created_at=datetime.fromtimestamp(now, timezone.utc),
                    expires_at=datetime.fromtimestamp(now + 120, timezone.utc),
                )
            ),
        )

    @fixtures.db.tenant(uuid=TENANT_UUID_1)
    def test_list_token_metadata_without_refresh_token(self, tenant_uuid):
        token_body = new_token_body()
        _, session_uuid = self._token_dao.create(
            token_body, {'tenant_uuid': TENANT_UUID_1}
        )

        result = self._session_dao.list_(tenant_uuids=[TENANT_UUID_1])
        assert_that(
            result,
            contains_exactly(
                has_entries(uuid=session_uuid, refresh_token_client_id=none())
            ),
        )

    @fixtures.db.tenant(uuid=TENANT_UUID_2)
    def test_list_sorting_on_token_columns(self, tenant_uuid):
        now = int(time.time())
        oldest = new_token_body(
            issued_t=now, expire_t=now + 60, user_agent='aaa-user-agent'
        )
        newest = new_token_body(
            issued_t=now + 60, expire_t=now + 300, user_agent='zzz-user-agent'
        )
        _, oldest_session_uuid = self._token_dao.create(
            oldest, {'tenant_uuid': TENANT_UUID_2}
        )
        _, newest_session_uuid = self._token_dao.create(
            newest, {'tenant_uuid': TENANT_UUID_2}
        )

        for column in ('created_at', 'expires_at', 'user_agent'):
            result = self._session_dao.list_(
                tenant_uuids=[TENANT_UUID_2], order=column, direction='asc'
            )
            assert_that(
                result,
                contains_exactly(
                    has_entries(uuid=oldest_session_uuid),
                    has_entries(uuid=newest_session_uuid),
                ),
                column,
            )

            result = self._session_dao.list_(
                tenant_uuids=[TENANT_UUID_2], order=column, direction='desc'
            )
            assert_that(
                result,
                contains_exactly(
                    has_entries(uuid=newest_session_uuid),
                    has_entries(uuid=oldest_session_uuid),
                ),
                column,
            )

    @fixtures.db.tenant(uuid=TENANT_UUID_3)
    def test_list_sorting_ties_are_broken_by_the_session_uuid(self, tenant_uuid):
        now = int(time.time())
        for _ in range(4):
            self._token_dao.create(
                new_token_body(issued_t=now, expire_t=now + 60, user_agent='same'),
                {'tenant_uuid': TENANT_UUID_3},
            )

        for direction in ('asc', 'desc'):
            result = self._session_dao.list_(
                tenant_uuids=[TENANT_UUID_3], order='user_agent', direction=direction
            )
            session_uuids = [session['uuid'] for session in result]
            assert_that(session_uuids, equal_to(sorted(session_uuids)), direction)
