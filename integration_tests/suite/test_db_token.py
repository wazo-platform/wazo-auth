# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time
import uuid

from contextlib import contextmanager
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
from .helpers import base, fixtures

SESSION_UUID_1 = str(uuid.uuid4())


def new_uuid():
    return str(uuid.uuid4())


def setup_module():
    base.DBStarter.setUpClass()


def teardown_module():
    base.DBStarter.tearDownClass()


class TestTokenDAO(base.DAOTestCase):

    def test_create(self):
        metadata = {
            'uuid': '08b213da-9963-4d25-96a3-f02d717e82f2',
            'id': 42,
            'msg': 'a string field',
        }

        with self._new_token(metadata=metadata) as e1, \
                self._new_token(acls=['first', 'second']) as e2:
            assert_that(e1['metadata'], has_entries(**metadata))
            t1 = self._token_dao.get(e1['uuid'])
            t2 = self._token_dao.get(e2['uuid'])
            assert_that(t1, equal_to(e1))
            assert_that(t2, equal_to(e2))

    def test_get(self):
        self.assertRaises(exceptions.UnknownTokenException, self._token_dao.get,
                          'unknown')
        with self._new_token(), self._new_token() as expected_token, self._new_token():
            token = self._token_dao.get(expected_token['uuid'])
        assert_that(token, equal_to(expected_token))

    def test_delete(self):
        with self._new_token() as token:
            self._token_dao.delete(token['uuid'])
            self.assertRaises(exceptions.UnknownTokenException, self._token_dao.get,
                              token['uuid'])
            self._token_dao.delete(token['uuid'])  # No error on delete unknown

    @fixtures.db.session()
    @fixtures.db.session()
    @fixtures.db.session(uuid=SESSION_UUID_1)
    @fixtures.db.token(expiration=0)
    @fixtures.db.token(expiration=0)
    @fixtures.db.token(session_uuid=SESSION_UUID_1)
    def test_delete_expired_tokens_and_sessions(self, token_1, token_2, token_3, session_1, session_2, session_3):
        with self._session_dao.new_session() as s:
            expired_tokens, expired_sessions = self._token_dao.delete_expired_tokens_and_sessions()

            assert_that(
                expired_tokens,
                all_of(
                    not_(has_items(has_entries(uuid=token_1['uuid']))),
                    has_items(has_entries(uuid=token_2['uuid'])),
                    has_items(has_entries(uuid=token_3['uuid'])),
                )
            )

            assert_that(
                expired_sessions,
                all_of(
                    not_(has_items(has_entries(uuid=session_1['uuid']))),
                    has_items(has_entries(uuid=session_2['uuid'])),
                    has_items(has_entries(uuid=session_3['uuid'])),
                )
            )

            sessions = s.query(models.Session).all()
            assert_that(
                sessions,
                all_of(
                    has_items(has_properties(uuid=session_1['uuid'])),
                    not_(has_items(has_properties(uuid=session_2['uuid']))),
                    not_(has_items(has_properties(uuid=session_3['uuid']))),
                )
            )

            tokens = s.query(models.Token).all()
            assert_that(
                tokens,
                all_of(
                    has_items(has_properties(uuid=token_1['uuid'])),
                    not_(has_items(has_properties(uuid=token_2['uuid']))),
                    not_(has_items(has_properties(uuid=token_3['uuid']))),
                )
            )

    @contextmanager
    def _new_token(self, acls=None, metadata=None, expiration=120):
        session_uuid = self._session_dao.create()
        now = int(time.time())
        body = {
            'auth_id': 'test',
            'xivo_user_uuid': new_uuid(),
            'xivo_uuid': new_uuid(),
            'issued_t': now,
            'expire_t': now + expiration,
            'acls': acls or [],
            'metadata': metadata or {},
            'session_uuid': session_uuid,
        }
        token_uuid = self._token_dao.create(body)
        token_data = dict(body)
        token_data['uuid'] = token_uuid
        yield token_data
        self._token_dao.delete(token_uuid)
