# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import uuid

from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    equal_to,
    empty,
    has_entries,
)
from .helpers import base, fixtures

TENANT_UUID_1 = str(uuid.uuid4())
SESSION_UUID_1 = str(uuid.uuid4())
SESSION_UUID_2 = str(uuid.uuid4())


def setup_module():
    base.DBStarter.setUpClass()


def teardown_module():
    base.DBStarter.tearDownClass()


class TestSessionDAO(base.DAOTestCase):

    @fixtures.db.tenant(uuid=TENANT_UUID_1)
    @fixtures.db.token(session={'mobile': False})
    @fixtures.db.token(session={'tenant_uuid': TENANT_UUID_1, 'mobile': True})
    def test_list(self, token_1, token_2, tenant_uuid):
        result = self._session_dao.list_()
        assert_that(result, contains_inanyorder(
            has_entries(
                uuid=token_1['session_uuid'],
                user_uuid=token_1['auth_id'],
                tenant_uuid=tenant_uuid,
            ),
            has_entries(
                uuid=token_2['session_uuid'],
                user_uuid=token_2['auth_id'],
            ),
        ))

        result = self._session_dao.list_(tenant_uuids=[TENANT_UUID_1])
        assert_that(result, contains_inanyorder(
            has_entries(uuid=token_1['session_uuid']),
        ))

        result = self._session_dao.list_(tenant_uuids=[])
        assert_that(result, empty())

        result = self._session_dao.list_(order='mobile', direction='desc')
        assert_that(result, contains(
            has_entries(uuid=token_1['session_uuid']),
            has_entries(uuid=token_2['session_uuid']),
        ))

        result = self._session_dao.list_(order='mobile', direction='asc', limit=1)
        assert_that(result, contains(
            has_entries(uuid=token_2['session_uuid']),
        ))

        result = self._session_dao.list_(order='mobile', direction='asc', offset=1)
        assert_that(result, contains(
            has_entries(uuid=token_1['session_uuid']),
        ))

        result = self._session_dao.list_(user_uuid=token_1['auth_id'])
        assert_that(result, contains(
            has_entries(uuid=token_1['session_uuid']),
        ))

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
