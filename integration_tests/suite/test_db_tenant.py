# Copyright 2018-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest

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
from mock import ANY

from wazo_test_helpers.mock import ANY_UUID
from wazo_auth import exceptions
from wazo_auth.database import models

from .helpers import fixtures, base, constants
from .helpers.base import (
    assert_no_error,
)

TENANT_UUID = '00000000-0000-4000-9000-000000000000'
USER_UUID = '00000000-0000-4000-9000-111111111111'
ADDRESS_ID = 42

TENANT_UUID_1 = '00000000-0000-4000-a000-000000000001'
TENANT_UUID_2 = '00000000-0000-4000-a000-000000000002'
TENANT_UUID_3 = '00000000-0000-4000-a000-000000000003'
TENANT_UUID_4 = '00000000-0000-4000-a000-000000000004'

VALID_DOMAIN_NAMES_1 = ['wazo.io', 'shopify.ca']
VALID_DOMAIN_NAMES_2 = ['gmail.com', 'yahoo.com', 'google.ca']
VALID_DOMAIN_NAMES_3 = ['outlook.fr', 'mail.yahoo.fr']


class ValidSlug:
    def __eq__(self, other):
        return other is not None and (0 < len(other) < 11)

    def __ne__(self, other):
        return not self.__eq__(other)


@base.use_asset('database')
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

    @fixtures.db.tenant(name='a', slug='zzz', domain_names=VALID_DOMAIN_NAMES_1)
    @fixtures.db.tenant(name='b', slug='yyy', domain_names=VALID_DOMAIN_NAMES_2)
    @fixtures.db.tenant(name='c', slug='xxx', domain_names=VALID_DOMAIN_NAMES_3)
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

        result = self._tenant_dao.count(visible_tenants, domain_name='shopify.ca')
        assert_that(result, equal_to(1))

        result = self._tenant_dao.count(visible_tenants, domain_name='google.ca')
        assert_that(result, equal_to(1))

        result = self._tenant_dao.count(visible_tenants, domain_name='outlook.fr')
        assert_that(result, equal_to(1))

        result = self._tenant_dao.count(visible_tenants, search='yahoo')
        assert_that(result, equal_to(2))

    @fixtures.db.tenant(name='baz a', domain_names=VALID_DOMAIN_NAMES_1)
    @fixtures.db.tenant(name='bar b', domain_names=VALID_DOMAIN_NAMES_2)
    @fixtures.db.tenant(name='foo c', domain_names=VALID_DOMAIN_NAMES_3)
    @fixtures.db.user()
    @fixtures.db.user()
    def test_list(self, a, b, c, user1_uuid, user2_uuid):
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

        result = self._tenant_dao.list_(search='yahoo')
        expected = build_list_matcher('bar b', 'foo c')
        assert_that(result, contains_inanyorder(*expected))

        result = self._tenant_dao.list_(domain_name='outlook.fr')
        expected = build_list_matcher('foo c')
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

    @fixtures.db.tenant(name='foobar', domain_names=VALID_DOMAIN_NAMES_1)
    def test_tenant_creation(self, foobar_uuid):
        # The parent_uuid defaults to the master tenant's UUID
        top_tenant_uuid = self._top_tenant_uuid()
        self._assert_tenant_matches(
            foobar_uuid, 'foobar', top_tenant_uuid, domain_names=VALID_DOMAIN_NAMES_1
        )

        # The parent_uuid can be specified
        foobaz_uuid = self._create_tenant(
            name='foobaz', parent_uuid=foobar_uuid, domain_names=VALID_DOMAIN_NAMES_2
        )
        try:
            self._assert_tenant_matches(
                foobaz_uuid, 'foobaz', foobar_uuid, domain_names=VALID_DOMAIN_NAMES_2
            )
        finally:
            self._tenant_dao.delete(foobaz_uuid)

        # The UUID can be specified
        c_uuid = self._create_tenant(
            uuid=uuid4(), name='c', domain_names=VALID_DOMAIN_NAMES_3
        )
        try:
            self._assert_tenant_matches(c_uuid, 'c', domain_names=VALID_DOMAIN_NAMES_3)
        finally:
            self._tenant_dao.delete(c_uuid)

        # Only one "master" tenant can exist
        uuid = uuid4()
        assert_that(
            calling(self._create_tenant).with_args(uuid=uuid, parent_uuid=uuid),
            raises(exceptions.MasterTenantConflictException),
        )

    @fixtures.db.tenant(name='foobar', domain_names=VALID_DOMAIN_NAMES_1)
    def test_tenants_with_duplicate_domain_names_creation_raises_409(self, foobar_uuid):

        uuid = uuid4()
        assert_that(
            calling(self._create_tenant).with_args(uuid=uuid, domain_names=['wazo.io']),
            raises(exceptions.DomainAlreadyExistException),
        )

    def test_tenant_creation_auto_generates_slug(self):
        tenant_uuid = self._create_tenant(
            name='t', slug=None, domain_names=VALID_DOMAIN_NAMES_1
        )

        try:
            self._assert_tenant_matches(
                tenant_uuid, 't', slug=ValidSlug(), domain_names=VALID_DOMAIN_NAMES_1
            )
        finally:
            self._tenant_dao.delete(tenant_uuid)

    @fixtures.db.tenant(domain_names=VALID_DOMAIN_NAMES_3)
    def test_delete(self, tenant_uuid):
        self._tenant_dao.delete(tenant_uuid)

        assert_that(
            calling(self._tenant_dao.delete).with_args(tenant_uuid),
            raises(exceptions.UnknownTenantException),
        )

    @fixtures.db.tenant(domain_names=VALID_DOMAIN_NAMES_1)
    def test_delete_tenant_with_children(self, tenant_uuid):

        a_uuid = self._create_tenant(
            name='a', parent_uuid=tenant_uuid, domain_names=VALID_DOMAIN_NAMES_2
        )

        assert_that(
            calling(self._tenant_dao.delete).with_args(tenant_uuid),
            raises(exceptions.UnauthorizedTenantwithChildrenDelete),
        )

        assert_no_error(self._tenant_dao.delete, a_uuid)

    @fixtures.db.tenant(uuid=TENANT_UUID)
    @fixtures.db.address(id_=ADDRESS_ID, tenant_uuid=TENANT_UUID)
    @fixtures.db.user(
        uuid=USER_UUID, tenant_uuid=TENANT_UUID, email_address='foo@bar.io'
    )
    @fixtures.db.policy(tenant_uuid=TENANT_UUID)
    @fixtures.db.external_auth_config(tenant_uuid=TENANT_UUID)
    @fixtures.db.user_external_auth(user_uuid=USER_UUID)
    def test_delete_sub_objects(
        self, tenant_uuid, address_id, user_uuid, policy_uuid, *_
    ):
        email_uuid = self._user_dao.get_emails(user_uuid)[0]['uuid']
        external_auth_config = (
            self.session.query(models.ExternalAuthConfig)
            .filter(models.ExternalAuthConfig.tenant_uuid == tenant_uuid)
            .first()
        )
        type_uuid = external_auth_config.type_uuid
        user_external_auth = (
            self.session.query(models.UserExternalAuth)
            .filter(models.UserExternalAuth.user_uuid == user_uuid)
            .first()
        )
        user_type_uuid = user_external_auth.external_auth_type_uuid

        self._tenant_dao.delete(tenant_uuid)

        result = self.session.query(models.User).get(user_uuid)
        assert_that(result, equal_to(None))
        result = self.session.query(models.Email).get(email_uuid)
        assert_that(result, equal_to(None))
        result = self.session.query(models.Address).get(address_id)
        assert_that(result, equal_to(None))
        result = self.session.query(models.ExternalAuthConfig).get(
            (tenant_uuid, type_uuid)
        )
        assert_that(result, equal_to(None))
        result = self.session.query(models.UserExternalAuth).get(
            (user_uuid, user_type_uuid)
        )
        assert_that(result, equal_to(None))
        result = self.session.query(models.Policy).get(policy_uuid)
        assert_that(result, equal_to(None))

    @pytest.mark.skip(reason="find a way to delete unused Access")
    @fixtures.db.tenant(uuid=TENANT_UUID)
    @fixtures.db.policy(tenant_uuid=TENANT_UUID, acl=['foo'])
    def test_delete_access(self, tenant_uuid, policy_uuid):
        access_policy = (
            self.session.query(models.PolicyAccess)
            .filter(models.PolicyAccess.policy_uuid == policy_uuid)
            .first()
        )
        access_id = access_policy.access_id

        self._tenant_dao.delete(tenant_uuid)

        result = self.session.query(models.PolicyAccess).get(access_id)
        assert_that(result, equal_to(None))

    def _assert_tenant_matches(
        self, uuid, name, parent_uuid=ANY_UUID, slug=ANY, domain_names=None
    ):

        assert_that(uuid, equal_to(ANY_UUID))
        s = self._tenant_dao.session
        tenant = (
            s.query(
                models.Tenant.name,
                models.Tenant.parent_uuid,
                models.Tenant.slug,
            )
            .filter(models.Tenant.uuid == uuid)
            .first()
        )

        assert_that(
            tenant,
            has_properties(name=name, parent_uuid=parent_uuid, slug=slug),
        )

        if domain_names:

            filter_ = models.Domain.name.in_(domain_names)
            names = s.query(models.Domain.name).filter(filter_).all()
            names = [name[0] for name in names]
            assert_that(sorted(domain_names), equal_to(sorted(names)))

    def _create_tenant(self, **kwargs):
        kwargs.setdefault('name', None)
        kwargs.setdefault('phone', None)
        kwargs.setdefault('slug', None)
        kwargs.setdefault('contact_uuid', None)
        kwargs.setdefault('domain_names', [])
        return self._tenant_dao.create(**kwargs)

    def _top_tenant_uuid(self):
        return (
            self.session.query(models.Tenant.uuid)
            .filter(models.Tenant.uuid == models.Tenant.parent_uuid)
            .scalar()
        )

    @fixtures.db.tenant(name='1', uuid=TENANT_UUID_1)
    @fixtures.db.tenant(name='2', uuid=TENANT_UUID_2, parent_uuid=TENANT_UUID_1)
    @fixtures.db.tenant(name='3', uuid=TENANT_UUID_3, parent_uuid=TENANT_UUID_1)
    @fixtures.db.tenant(name='4', uuid=TENANT_UUID_4, parent_uuid=TENANT_UUID_2)
    def test_tenant_query_always_return_scoped_tenant_first(self, *_):
        result = self._tenant_dao._tenant_query(TENANT_UUID_2)
        assert_that(result[0], has_properties(name='2'))

        self._tenant_dao.update(TENANT_UUID_2, name='2-updated')

        result = self._tenant_dao._tenant_query(TENANT_UUID_2)
        assert_that(result[0], has_properties(name='2-updated'))

    @fixtures.db.tenant(name='1', uuid=TENANT_UUID_1, domain_names=VALID_DOMAIN_NAMES_1)
    def test_update_tenant_domain_names(self, *_):

        self._tenant_dao.update(
            TENANT_UUID_1, name='1-updated', domain_names=['wazo.io']
        )

        self._assert_tenant_matches(
            TENANT_UUID_1, '1-updated', domain_names=['wazo.io']
        )

    @fixtures.db.tenant(name='1', uuid=TENANT_UUID_1, domain_names=VALID_DOMAIN_NAMES_1)
    @fixtures.db.tenant(name='2', uuid=TENANT_UUID_2, domain_names=VALID_DOMAIN_NAMES_2)
    def test_update_tenant_with_duplicate_domain_names_raises_409(self, *_):

        assert_that(
            calling(self._tenant_dao.update).with_args(
                tenant_uuid=TENANT_UUID_2, domain_names=['wazo.io']
            ),
            raises(exceptions.DomainAlreadyExistException),
        )
