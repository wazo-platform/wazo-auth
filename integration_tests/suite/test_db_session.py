# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import uuid

from hamcrest import (
    all_of,
    assert_that,
    contains,
    contains_inanyorder,
    equal_to,
    empty,
    has_entries,
    has_items,
    has_properties,
    is_not,
    none,
    not_,
)
from wazo_auth.database import models
from .helpers import base, fixtures

TENANT_UUID_1 = str(uuid.uuid4())
SESSION_UUID_1 = str(uuid.uuid4())


def setup_module():
    base.DBStarter.setUpClass()


def teardown_module():
    base.DBStarter.tearDownClass()


class TestSessionDAO(base.DAOTestCase):

    def test_create(self):
        session_uuid = self._session_dao.create()
        assert_that(session_uuid, is_not(none()))

    @fixtures.db.tenant(uuid=TENANT_UUID_1)
    @fixtures.db.session(mobile=False)
    @fixtures.db.session(tenant_uuid=TENANT_UUID_1, mobile=True)
    def test_list(self, session_1, session_2, _):
        result = self._session_dao.list_()
        assert_that(result, contains_inanyorder(
            has_entries(uuid=session_1['uuid']),
            has_entries(uuid=session_2['uuid']),
        ))

        result = self._session_dao.list_(tenant_uuids=[TENANT_UUID_1])
        assert_that(result, contains_inanyorder(
            has_entries(uuid=session_1['uuid']),
        ))

        result = self._session_dao.list_(tenant_uuids=[])
        assert_that(result, empty())

        result = self._session_dao.list_(order='mobile', direction='desc')
        assert_that(result, contains(
            has_entries(uuid=session_1['uuid']),
            has_entries(uuid=session_2['uuid']),
        ))

        result = self._session_dao.list_(order='mobile', direction='asc', limit=1)
        assert_that(result, contains(
            has_entries(uuid=session_2['uuid']),
        ))

        result = self._session_dao.list_(order='mobile', direction='asc', offset=1)
        assert_that(result, contains(
            has_entries(uuid=session_1['uuid']),
        ))

    @fixtures.db.tenant(uuid=TENANT_UUID_1)
    @fixtures.db.session(tenant_uuid=TENANT_UUID_1)
    @fixtures.db.session()
    def test_count(self, *_):
        result = self._session_dao.count()
        assert_that(result, equal_to(2))

        result = self._session_dao.count(tenant_uuids=[TENANT_UUID_1])
        assert_that(result, equal_to(1))

        result = self._session_dao.count(tenant_uuids=[])
        assert_that(result, equal_to(0))

    @fixtures.db.session()
    @fixtures.db.session(uuid=SESSION_UUID_1)
    @fixtures.db.token(session_uuid=SESSION_UUID_1)
    def test_delete_expired(self, _, session_1, session_2):
        with self._session_dao.new_session() as s:
            sessions = s.query(models.Session).all()
            assert_that(
                sessions,
                has_items(
                    has_properties(uuid=session_1['uuid']),
                    has_properties(uuid=session_2['uuid']),
                )
            )

            result = self._session_dao.delete_expired()

            assert_that(result, has_items(has_entries(uuid=session_2['uuid']))),

            sessions = s.query(models.Session).all()
            assert_that(
                sessions,
                all_of(
                    has_items(has_properties(uuid=session_1['uuid'])),
                    not_(has_items(has_properties(uuid=session_2['uuid']))),
                )
            )
