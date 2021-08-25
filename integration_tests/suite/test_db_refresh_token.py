# Copyright 2016-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import datetime
import uuid

from hamcrest import assert_that, contains_inanyorder, empty, equal_to, has_entries
from .helpers import fixtures, base

ALICE_UUID = str(uuid.uuid4())
TENANT_UUID = str(uuid.uuid4())
CREATED_AT = datetime.datetime.now()


@base.use_asset('database')
class TestRefreshTokenDAO(base.DAOTestCase):
    @fixtures.db.tenant(uuid=TENANT_UUID)
    @fixtures.db.user(uuid=ALICE_UUID, username='alice', tenant_uuid=TENANT_UUID)
    @fixtures.db.user(username='bob', tenant_uuid=TENANT_UUID)
    @fixtures.db.refresh_token(user_uuid=ALICE_UUID)
    @fixtures.db.refresh_token(user_uuid=ALICE_UUID, created_at=CREATED_AT)
    @fixtures.db.refresh_token(user_uuid=ALICE_UUID, client_id='foobar')
    def test_count(self, tenant, alice_uuid, bob_uuid, token_1, token_2, token_3):
        result = self._refresh_token_dao.count(user_uuid=ALICE_UUID)
        assert_that(result, equal_to(3))

        result = self._refresh_token_dao.count(user_uuid=bob_uuid)
        assert_that(result, equal_to(0))

        result = self._refresh_token_dao.count(user_uuid=ALICE_UUID, tenant_uuids=[])
        assert_that(result, equal_to(0))

        result = self._refresh_token_dao.count(user_uuid=ALICE_UUID, tenant_uuids=None)
        assert_that(result, equal_to(3))

        result = self._refresh_token_dao.count(
            user_uuid=ALICE_UUID, tenant_uuids=[TENANT_UUID]
        )
        assert_that(result, equal_to(3))

        result = self._refresh_token_dao.count(
            user_uuid=ALICE_UUID, tenant_uuids=[self.top_tenant_uuid, TENANT_UUID]
        )
        assert_that(result, equal_to(3))

        result = self._refresh_token_dao.count(
            user_uuid=ALICE_UUID, filtered=True, client_id='foobar'
        )
        assert_that(result, equal_to(1))

        result = self._refresh_token_dao.count(
            user_uuid=ALICE_UUID, filtered=True, created_at=CREATED_AT
        )
        assert_that(result, equal_to(1))

        result = self._refresh_token_dao.count(
            user_uuid=ALICE_UUID, filtered=False, client_id='foobar'
        )
        assert_that(result, equal_to(3))

        result = self._refresh_token_dao.count(
            user_uuid=ALICE_UUID, filtered=False, uuid=token_1
        )
        assert_that(result, equal_to(3))

        result = self._refresh_token_dao.count(
            user_uuid=ALICE_UUID, filtered=False, created_at=CREATED_AT
        )
        assert_that(result, equal_to(3))

        result = self._refresh_token_dao.count(
            user_uuid=ALICE_UUID, filtered=True, search='foo'
        )
        assert_that(result, equal_to(1))

        result = self._refresh_token_dao.count(
            user_uuid=ALICE_UUID, filtered=False, search='foo'
        )
        assert_that(result, equal_to(3))

    @fixtures.db.tenant(uuid=TENANT_UUID)
    @fixtures.db.user(uuid=ALICE_UUID, username='alice', tenant_uuid=TENANT_UUID)
    @fixtures.db.user(username='bob', tenant_uuid=TENANT_UUID)
    @fixtures.db.refresh_token(user_uuid=ALICE_UUID, mobile=True)
    @fixtures.db.refresh_token(user_uuid=ALICE_UUID, created_at=CREATED_AT)
    @fixtures.db.refresh_token(user_uuid=ALICE_UUID, client_id='foobar')
    def test_list(self, tenant, alice_uuid, bob_uuid, token_1, token_2, token_3):
        all_refresh_tokens = contains_inanyorder(
            has_entries(uuid=token_1),
            has_entries(uuid=token_2),
            has_entries(uuid=token_3),
        )

        result = self._refresh_token_dao.list_(user_uuid=ALICE_UUID)
        assert_that(result, all_refresh_tokens)

        result = self._refresh_token_dao.list_(user_uuid=bob_uuid)
        assert_that(result, empty())

        result = self._refresh_token_dao.list_(user_uuid=ALICE_UUID, tenant_uuids=[])
        assert_that(result, empty())

        result = self._refresh_token_dao.list_(user_uuid=ALICE_UUID, tenant_uuids=None)
        assert_that(result, all_refresh_tokens)

        result = self._refresh_token_dao.list_(
            user_uuid=ALICE_UUID, tenant_uuids=[TENANT_UUID]
        )
        assert_that(result, all_refresh_tokens)

        result = self._refresh_token_dao.list_(
            user_uuid=ALICE_UUID, tenant_uuids=[self.top_tenant_uuid, TENANT_UUID]
        )
        assert_that(result, all_refresh_tokens)

        result = self._refresh_token_dao.list_(user_uuid=ALICE_UUID, client_id='foobar')
        assert_that(result, contains_inanyorder(has_entries(uuid=token_3)))

        result = self._refresh_token_dao.list_(
            user_uuid=ALICE_UUID, created_at=CREATED_AT
        )
        assert_that(result, contains_inanyorder(has_entries(uuid=token_2)))

        result = self._refresh_token_dao.list_(
            user_uuid=ALICE_UUID,
            mobile=True,
        )
        assert_that(result, contains_inanyorder(has_entries(uuid=token_1)))

        result = self._refresh_token_dao.list_(user_uuid=ALICE_UUID, search='foo')
        assert_that(result, contains_inanyorder(has_entries(uuid=token_3)))
