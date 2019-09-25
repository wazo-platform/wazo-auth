# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time
import uuid

from hamcrest import (
    all_of,
    assert_that,
    equal_to,
    has_entries,
    has_items,
    has_properties,
    not_,
)

from wazo_auth import exceptions
from wazo_auth.database import models
from ..helpers import base, fixtures

SESSION_UUID_1 = str(uuid.uuid4())


class TestTokenDAO(base.DAOTestCase):
    def test_create(self):
        now = int(time.time())
        body = {
            'auth_id': 'test',
            'xivo_user_uuid': str(uuid.uuid4),
            'xivo_uuid': str(uuid.uuid4),
            'issued_t': now,
            'expire_t': now + 120,
            'acls': ['first', 'second'],
            'metadata': {
                'uuid': '08b213da-9963-4d25-96a3-f02d717e82f2',
                'id': 42,
                'msg': 'a string field',
            },
            'user_agent': 'my-user-agent',
            'remote_addr': '192.168.1.1',
        }
        session = {}
        token_uuid, session_uuid = self._token_dao.create(body, session)

        result = self._token_dao.get(token_uuid)
        assert_that(
            result, has_entries(uuid=token_uuid, session_uuid=session_uuid, **body)
        )

    @fixtures.db.token()
    @fixtures.db.token()
    @fixtures.db.token()
    def test_get(self, token, *_):
        self.assertRaises(
            exceptions.UnknownTokenException, self._token_dao.get, 'unknown'
        )
        result = self._token_dao.get(token['uuid'])
        assert_that(result, equal_to(token))

    @fixtures.db.token()
    def test_delete(self, token):
        self._token_dao.delete(token['uuid'])
        self.assertRaises(
            exceptions.UnknownTokenException, self._token_dao.get, token['uuid']
        )
        self._token_dao.delete(token['uuid'])  # No error on delete unknown

    @fixtures.db.token(expiration=0)
    @fixtures.db.token(expiration=0)
    @fixtures.db.token()
    def test_delete_expired_tokens_and_sessions(self, token_1, token_2, token_3):
        with self._session_dao.new_session() as s:
            expired_tokens, expired_sessions = (
                self._token_dao.delete_expired_tokens_and_sessions()
            )

            assert_that(
                expired_tokens,
                all_of(
                    not_(has_items(has_entries(uuid=token_1['uuid']))),
                    has_items(has_entries(uuid=token_2['uuid'])),
                    has_items(has_entries(uuid=token_3['uuid'])),
                ),
            )

            assert_that(
                expired_sessions,
                all_of(
                    not_(has_items(has_entries(uuid=token_1['session_uuid']))),
                    has_items(has_entries(uuid=token_2['session_uuid'])),
                    has_items(has_entries(uuid=token_3['session_uuid'])),
                ),
            )

            sessions = s.query(models.Session).all()
            assert_that(
                sessions,
                all_of(
                    has_items(has_properties(uuid=token_1['session_uuid'])),
                    not_(has_items(has_properties(uuid=token_2['session_uuid']))),
                    not_(has_items(has_properties(uuid=token_3['session_uuid']))),
                ),
            )

            tokens = s.query(models.Token).all()
            assert_that(
                tokens,
                all_of(
                    has_items(has_properties(uuid=token_1['uuid'])),
                    not_(has_items(has_properties(uuid=token_2['uuid']))),
                    not_(has_items(has_properties(uuid=token_3['uuid']))),
                ),
            )
