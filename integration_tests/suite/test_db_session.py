# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import uuid

from hamcrest import (
    all_of,
    assert_that,
    has_items,
    has_properties,
    is_not,
    none,
    not_,
)
from wazo_auth.database import models
from .helpers import base, fixtures

SESSION_UUID_1 = str(uuid.uuid4())


def setup_module():
    base.DBStarter.setUpClass()


def teardown_module():
    base.DBStarter.tearDownClass()


class TestSessionDAO(base.DAOTestCase):

    def test_create(self):
        tenant_uuid = self._session_dao.create()
        assert_that(tenant_uuid, is_not(none()))

    @fixtures.session()
    @fixtures.session(uuid=SESSION_UUID_1)
    @fixtures.token(session_uuid=SESSION_UUID_1)
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

            self._session_dao.delete_expired()

            sessions = s.query(models.Session).all()
            assert_that(
                sessions,
                all_of(
                    has_items(has_properties(uuid=session_1['uuid'])),
                    not_(has_items(has_properties(uuid=session_2['uuid']))),
                )
            )
