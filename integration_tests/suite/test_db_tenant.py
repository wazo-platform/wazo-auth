# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from uuid import uuid4

from hamcrest import (
    assert_that,
    calling,
    contains,
    contains_inanyorder,
    equal_to,
    has_entries,
    has_properties,
    raises,
)

from xivo_test_helpers.mock import ANY_UUID
from wazo_auth import exceptions
from wazo_auth.database import models

from .helpers import fixtures, base


def setup_module():
    base.DBStarter.setUpClass()


def teardown_module():
    base.DBStarter.tearDownClass()


class TestTenantDAO(base.DAOTestCase):

    @fixtures.tenant(name='c')
    @fixtures.tenant(name='b')
    @fixtures.tenant(name='a')
    def test_count(self, *tenants):
        top_tenant_uuid = self._top_tenant_uuid()
        visible_tenants = tenants + (top_tenant_uuid,)
        total = len(tenants) + 1  # a, b, c and the master tenant

        result = self._tenant_dao.count(visible_tenants)
        assert_that(result, equal_to(total))

        result = self._tenant_dao.count(visible_tenants, search='b', filtered=False)
        assert_that(result, equal_to(total))

        result = self._tenant_dao.count(visible_tenants, search='b')
        assert_that(result, equal_to(1))

        result = self._tenant_dao.count(visible_tenants, name='b', filtered=False)
        assert_that(result, equal_to(total))

        result = self._tenant_dao.count(visible_tenants, name='b')
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
        expected = build_list_matcher('foo c', 'bar b', 'baz a', 'master')
        assert_that(result, contains_inanyorder(*expected))

        result = self._tenant_dao.list_(tenant_uuids=[a, b])
        expected = build_list_matcher('bar b', 'baz a')
        assert_that(result, contains_inanyorder(*expected))

        result = self._tenant_dao.list_()
        expected = build_list_matcher('foo c', 'bar b', 'baz a', 'master')
        assert_that(result, contains_inanyorder(*expected))

        result = self._tenant_dao.list_(search='ba')
        expected = build_list_matcher('bar b', 'baz a')
        assert_that(result, contains_inanyorder(*expected))

        result = self._tenant_dao.list_(order='name', direction='desc')
        expected = build_list_matcher('master', 'foo c', 'baz a', 'bar b')
        assert_that(result, contains(*expected))

        result = self._tenant_dao.list_(limit=1, order='name', direction='asc')
        expected = build_list_matcher('bar b')
        assert_that(result, contains(*expected))

        result = self._tenant_dao.list_(offset=1, order='name', direction='asc')
        expected = build_list_matcher('baz a', 'foo c', 'master')
        assert_that(result, contains(*expected))

    @fixtures.tenant(name='foobar')
    def test_tenant_creation(self, foobar_uuid):
        # The parent_uuid defaults to the master tenant's UUID
        top_tenant_uuid = self._top_tenant_uuid()
        self._assert_tenant_matches(foobar_uuid, 'foobar', top_tenant_uuid)

        # The parent_uuid can be specified
        foobaz_uuid = self._create_tenant(name='foobaz', parent_uuid=foobar_uuid)
        try:
            self._assert_tenant_matches(foobaz_uuid, 'foobaz', foobar_uuid)
        finally:
            self._tenant_dao.delete(foobaz_uuid)

        # The UUID can be specified
        c_uuid = self._create_tenant(uuid=uuid4(), name='c')
        try:
            self._assert_tenant_matches(c_uuid, 'c')
        finally:
            self._tenant_dao.delete(c_uuid)

        # Only one "master" tenant can exist
        uuid = uuid4()
        assert_that(
            calling(self._create_tenant).with_args(uuid=uuid, parent_uuid=uuid),
            raises(exceptions.MasterTenantConflictException),
        )

    @fixtures.tenant()
    def test_delete(self, tenant_uuid):
        self._tenant_dao.delete(tenant_uuid)

        assert_that(
            calling(self._tenant_dao.delete).with_args(tenant_uuid),
            raises(exceptions.UnknownTenantException),
        )

    def _assert_tenant_matches(self, uuid, name, parent_uuid=ANY_UUID):
        assert_that(uuid, equal_to(ANY_UUID))
        with self._tenant_dao.new_session() as s:
            tenant = s.query(
                models.Tenant.name,
                models.Tenant.parent_uuid,
            ).filter(
                models.Tenant.uuid == uuid
            ).first()

            assert_that(
                tenant,
                has_properties(name=name, parent_uuid=parent_uuid),
            )

    def _create_tenant(self, **kwargs):
        kwargs.setdefault('name', None)
        kwargs.setdefault('phone', None)
        kwargs.setdefault('contact_uuid', None)
        kwargs.setdefault('address_id', None)
        return self._tenant_dao.create(**kwargs)

    def _top_tenant_uuid(self):
        with self._tenant_dao.new_session() as s:
            return s.query(
                models.Tenant.uuid,
            ).filter(
                models.Tenant.uuid == models.Tenant.parent_uuid
            ).scalar()
