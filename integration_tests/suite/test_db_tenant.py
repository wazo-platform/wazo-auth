# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from uuid import UUID

from hamcrest import (
    assert_that,
    calling,
    contains,
    contains_inanyorder,
    empty,
    equal_to,
    has_entries,
    has_properties,
    raises,
)

from xivo_test_helpers.mock import ANY_UUID
from wazo_auth import exceptions
from wazo_auth.database import models

from .helpers import fixtures, base


def setup():
    base.DBStarter.setUpClass()


def teardown():
    base.DBStarter.tearDownClass()


class TestTenantDAO(base.DAOTestCase):

    @fixtures.tenant()
    @fixtures.policy()
    def test_add_policy(self, policy_uuid, tenant_uuid):
        assert_that(self._policy_dao.list_(tenant_uuid=tenant_uuid), empty())

        self._tenant_dao.add_policy(tenant_uuid, policy_uuid)
        assert_that(
            self._policy_dao.list_(tenant_uuid=tenant_uuid),
            contains(has_entries('uuid', policy_uuid)),
        )

        self._tenant_dao.add_policy(tenant_uuid, policy_uuid)  # twice

        assert_that(
            calling(self._tenant_dao.add_policy).with_args(self.unknown_uuid, policy_uuid),
            raises(exceptions.UnknownTenantException),
            'unknown tenant',
        )

        assert_that(
            calling(self._tenant_dao.add_policy).with_args(tenant_uuid, self.unknown_uuid),
            raises(exceptions.UnknownPolicyException),
            'unknown policy',
        )

    @fixtures.tenant()
    @fixtures.user()
    def test_add_user(self, user_uuid, tenant_uuid):
        assert_that(self._user_dao.list_(tenant_uuid=tenant_uuid), empty())

        self._tenant_dao.add_user(tenant_uuid, user_uuid)
        assert_that(self._user_dao.list_(tenant_uuid=tenant_uuid), contains(has_entries('uuid', user_uuid)))

        self._tenant_dao.add_user(tenant_uuid, user_uuid)  # twice

        assert_that(
            calling(self._tenant_dao.add_user).with_args(self.unknown_uuid, user_uuid),
            raises(exceptions.UnknownTenantException),
            'unknown tenant',
        )

        assert_that(
            calling(self._tenant_dao.add_user).with_args(tenant_uuid, self.unknown_uuid),
            raises(exceptions.UnknownUserException),
            'unknown user',
        )

    @fixtures.tenant()
    @fixtures.policy()
    def test_remove_policy(self, policy_uuid, tenant_uuid):
        result = self._tenant_dao.remove_policy(tenant_uuid, policy_uuid)
        assert_that(result, equal_to(0))

        self._tenant_dao.add_policy(tenant_uuid, policy_uuid)

        result = self._tenant_dao.remove_policy(self.unknown_uuid, policy_uuid)
        assert_that(result, equal_to(0))

        result = self._tenant_dao.remove_policy(tenant_uuid, self.unknown_uuid)
        assert_that(result, equal_to(0))

        result = self._tenant_dao.remove_policy(tenant_uuid, policy_uuid)
        assert_that(result, equal_to(1))

    @fixtures.tenant()
    @fixtures.user()
    def test_remove_user(self, user_uuid, tenant_uuid):
        result = self._tenant_dao.remove_user(tenant_uuid, user_uuid)
        assert_that(result, equal_to(0))

        self._tenant_dao.add_user(tenant_uuid, user_uuid)

        result = self._tenant_dao.remove_user(self.unknown_uuid, user_uuid)
        assert_that(result, equal_to(0))

        result = self._tenant_dao.remove_user(tenant_uuid, self.unknown_uuid)
        assert_that(result, equal_to(0))

        result = self._tenant_dao.remove_user(tenant_uuid, user_uuid)
        assert_that(result, equal_to(1))

    @fixtures.tenant(name='c')
    @fixtures.tenant(name='b')
    @fixtures.tenant(name='a')
    def test_count(self, a, b, c):
        result = self._tenant_dao.count()
        assert_that(result, equal_to(3))

        result = self._tenant_dao.count(search='a', filtered=False)
        assert_that(result, equal_to(3))

        result = self._tenant_dao.count(search='a')
        assert_that(result, equal_to(1))

        result = self._tenant_dao.count(name='a', filtered=False)
        assert_that(result, equal_to(3))

        result = self._tenant_dao.count(name='a')
        assert_that(result, equal_to(1))

    @fixtures.tenant(name='foo c')
    @fixtures.tenant(name='bar b')
    @fixtures.tenant(name='baz a')
    @fixtures.user()
    @fixtures.user()
    def test_list(self, user1_uuid, user2_uuid, a, b, c):
        def build_list_matcher(*names):
            return [has_entries(name=name, address=base.ADDRESS_NULL) for name in names]

        result = self._tenant_dao.list_()
        expected = build_list_matcher('foo c', 'bar b', 'baz a')
        assert_that(result, contains_inanyorder(*expected))

        for tenant_uuid in (a, b, c):
            self._tenant_dao.add_user(tenant_uuid, user1_uuid)
            self._tenant_dao.add_user(tenant_uuid, user2_uuid)

        result = self._tenant_dao.list_()
        expected = build_list_matcher('foo c', 'bar b', 'baz a')
        assert_that(result, contains_inanyorder(*expected))

        result = self._tenant_dao.list_(search='ba')
        expected = build_list_matcher('bar b', 'baz a')
        assert_that(result, contains_inanyorder(*expected))

        result = self._tenant_dao.list_(order='name', direction='desc')
        expected = build_list_matcher('foo c', 'baz a', 'bar b')
        assert_that(result, contains(*expected))

        result = self._tenant_dao.list_(limit=1, order='name', direction='asc')
        expected = build_list_matcher('bar b')
        assert_that(result, contains(*expected))

        result = self._tenant_dao.list_(offset=1, order='name', direction='asc')
        expected = build_list_matcher('baz a', 'foo c')
        assert_that(result, contains(*expected))

    @fixtures.tenant(name='foobar')
    def test_tenant_creation(self, tenant_uuid):
        name = 'foobar'

        assert_that(tenant_uuid, equal_to(ANY_UUID))
        with self._tenant_dao.new_session() as s:
            tenant = s.query(
                models.Tenant,
            ).filter(
                models.Tenant.uuid == tenant_uuid
            ).first()

            assert_that(tenant, has_properties(name=name))

    @fixtures.tenant(uuid=UUID('b7a17bb9-6925-4073-a346-1bc8f8e4f805'), name='foobar')
    def test_tenant_creation_with_a_uuid(self, tenant_uuid):
        name = 'foobar'

        assert_that(tenant_uuid, equal_to('b7a17bb9-6925-4073-a346-1bc8f8e4f805'))
        with self._tenant_dao.new_session() as s:
            tenant = s.query(
                models.Tenant,
            ).filter(
                models.Tenant.uuid == tenant_uuid
            ).first()

            assert_that(tenant, has_properties(name=name, uuid=tenant_uuid))

    @fixtures.tenant()
    def test_delete(self, tenant_uuid):
        self._tenant_dao.delete(tenant_uuid)

        assert_that(
            calling(self._tenant_dao.delete).with_args(tenant_uuid),
            raises(exceptions.UnknownTenantException),
        )
