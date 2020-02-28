# Copyright 2018-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from uuid import uuid4

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

from ..helpers import fixtures, base, constants


class TestTenantDAO(base.DAOTestCase):
    def test_tenant_segregation(self):
        # This test will use the following tenant scructure
        #         top
        #       /  |  \
        #      a   e   h
        #     / \  |
        #    d  b  f
        #       /\
        #      g  c

        top_uuid = self._top_tenant_uuid()
        a_uuid = self._create_tenant(name='a', parent_uuid=top_uuid)
        e_uuid = self._create_tenant(name='e', parent_uuid=top_uuid)
        h_uuid = self._create_tenant(name='h', parent_uuid=top_uuid)
        d_uuid = self._create_tenant(name='d', parent_uuid=a_uuid)
        b_uuid = self._create_tenant(name='b', parent_uuid=a_uuid)
        f_uuid = self._create_tenant(name='f', parent_uuid=e_uuid)
        g_uuid = self._create_tenant(name='g', parent_uuid=b_uuid)
        c_uuid = self._create_tenant(name='c', parent_uuid=b_uuid)

        # No scoping tenant returns all tenants
        result = self._tenant_dao.list_visible_tenants()
        assert_that(
            result,
            contains_inanyorder(
                has_properties(uuid=top_uuid),
                has_properties(uuid=a_uuid),
                has_properties(uuid=b_uuid),
                has_properties(uuid=c_uuid),
                has_properties(uuid=d_uuid),
                has_properties(uuid=e_uuid),
                has_properties(uuid=f_uuid),
                has_properties(uuid=g_uuid),
                has_properties(uuid=h_uuid),
            ),
        )

        # Top tenant sees everyone
        result = self._tenant_dao.list_visible_tenants(scoping_tenant_uuid=top_uuid)
        assert_that(
            result,
            contains_inanyorder(
                has_properties(uuid=top_uuid),
                has_properties(uuid=a_uuid),
                has_properties(uuid=b_uuid),
                has_properties(uuid=c_uuid),
                has_properties(uuid=d_uuid),
                has_properties(uuid=e_uuid),
                has_properties(uuid=f_uuid),
                has_properties(uuid=g_uuid),
                has_properties(uuid=h_uuid),
            ),
        )

        # Leaves can see themselves only
        result = self._tenant_dao.list_visible_tenants(scoping_tenant_uuid=c_uuid)
        assert_that(result, contains(has_properties(uuid=c_uuid)))

        # An unknown tenant returns nothing
        result = self._tenant_dao.list_visible_tenants(
            scoping_tenant_uuid=constants.UNKNOWN_UUID
        )
        assert_that(result, empty())

        # A tenant sees all of its subtenant and itself
        result = self._tenant_dao.list_visible_tenants(scoping_tenant_uuid=a_uuid)
        assert_that(
            result,
            contains_inanyorder(
                has_properties(uuid=a_uuid),
                has_properties(uuid=b_uuid),
                has_properties(uuid=c_uuid),
                has_properties(uuid=d_uuid),
                has_properties(uuid=g_uuid),
            ),
        )

    @fixtures.db.tenant(name='c')
    @fixtures.db.tenant(name='b')
    @fixtures.db.tenant(name='a')
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

    @fixtures.db.tenant(name='foo c')
    @fixtures.db.tenant(name='bar b')
    @fixtures.db.tenant(name='baz a')
    @fixtures.db.user()
    @fixtures.db.user()
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

    @fixtures.db.tenant(name='foobar')
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

    @fixtures.db.tenant()
    def test_delete(self, tenant_uuid):
        self._tenant_dao.delete(tenant_uuid)

        assert_that(
            calling(self._tenant_dao.delete).with_args(tenant_uuid),
            raises(exceptions.UnknownTenantException),
        )

    def _assert_tenant_matches(self, uuid, name, parent_uuid=ANY_UUID):
        assert_that(uuid, equal_to(ANY_UUID))
        s = self._tenant_dao.session
        tenant = (
            s.query(models.Tenant.name, models.Tenant.parent_uuid)
            .filter(models.Tenant.uuid == uuid)
            .first()
        )

        assert_that(tenant, has_properties(name=name, parent_uuid=parent_uuid))

    def _create_tenant(self, **kwargs):
        kwargs.setdefault('name', None)
        kwargs.setdefault('phone', None)
        kwargs.setdefault('contact_uuid', None)
        kwargs.setdefault('address_id', None)
        return self._tenant_dao.create(**kwargs)

    def _top_tenant_uuid(self):
        return (
            self.session.query(models.Tenant.uuid)
            .filter(models.Tenant.uuid == models.Tenant.parent_uuid)
            .scalar()
        )
