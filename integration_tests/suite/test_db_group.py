# Copyright 2016-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from contextlib import contextmanager

from hamcrest import (
    assert_that,
    calling,
    contains_exactly,
    contains_inanyorder,
    empty,
    equal_to,
    has_entries,
    has_properties,
    not_,
)
from wazo_test_helpers.hamcrest.raises import raises
from wazo_test_helpers.mock import ANY_UUID

from wazo_auth import exceptions
from wazo_auth.database import models

from .helpers import base, fixtures

USER_UUID = '00000000-0000-4000-9000-111111111111'
TENANT_UUID = 'a26c4ed8-767f-463e-a10a-42c4f220d375'


@base.use_asset('database')
class TestGroupDAO(base.DAOTestCase):
    @fixtures.db.group()
    @fixtures.db.policy()
    def test_add_policy(self, group_uuid, policy_uuid):
        assert_that(self._policy_dao.list_(group_uuid=group_uuid), empty())

        self._group_dao.add_policy(group_uuid, policy_uuid)
        result = self._policy_dao.list_(group_uuid=group_uuid)
        assert_that(result, contains_exactly(has_properties(uuid=policy_uuid)))

        self._group_dao.add_policy(group_uuid, policy_uuid)  # twice

        assert_that(
            calling(self._group_dao.add_policy).with_args(
                self.unknown_uuid, policy_uuid
            ),
            raises(exceptions.UnknownGroupException),
            'unknown group',
        )

        assert_that(
            calling(self._group_dao.add_policy).with_args(
                group_uuid, self.unknown_uuid
            ),
            raises(exceptions.UnknownPolicyException),
            'unknown policy',
        )

    @fixtures.db.group()
    @fixtures.db.user()
    def test_add_user(self, group_uuid, user_uuid):
        assert_that(self._user_dao.list_(group_uuid=group_uuid), empty())

        self._group_dao.add_user(group_uuid, user_uuid)
        result = self._user_dao.list_(group_uuid=group_uuid)
        assert_that(result, contains_exactly(has_entries(uuid=user_uuid)))

        self._group_dao.add_user(group_uuid, user_uuid)  # twice

        assert_that(
            calling(self._group_dao.add_user).with_args(self.unknown_uuid, user_uuid),
            raises(exceptions.UnknownGroupException),
            'unknown group',
        )

        assert_that(
            calling(self._group_dao.add_user).with_args(group_uuid, self.unknown_uuid),
            raises(exceptions.UnknownUserException),
            'unknown user',
        )

    @fixtures.db.group(name='foo')
    @fixtures.db.group(name='bar')
    @fixtures.db.group(name='baz')
    def test_count(self, *ignored):
        result = self._group_dao.count()
        assert_that(result, equal_to(3))

        result = self._group_dao.count(name='foo', filtered=False)
        assert_that(result, equal_to(3))

        result = self._group_dao.count(search='ba', filtered=False)
        assert_that(result, equal_to(3))

        result = self._group_dao.count(name='foo', filtered=True)
        assert_that(result, equal_to(1))

        result = self._group_dao.count(search='ba', filtered=True)
        assert_that(result, equal_to(2))

    @fixtures.db.user()
    @fixtures.db.user()
    @fixtures.db.group()
    def test_count_users(self, user1, user2, group):
        self._group_dao.add_user(group, user1)
        self._group_dao.add_user(group, user2)

        result = self._group_dao.count_users(group)
        assert_that(result, equal_to(2))

    @fixtures.db.user(uuid=USER_UUID, email_address='user1-1@example.com')
    @fixtures.db.group()
    @fixtures.db.email(user_uuid=USER_UUID, address='user1-2@example.com')
    def test_count_users_with_user_many_emails(self, user, group, *_):
        self._group_dao.add_user(group, user)

        result = self._group_dao.count_users(group)
        assert_that(result, equal_to(1))

        result = self._group_dao.count_users(
            group,
            filtered=True,
            email_address='user1-1@example.com',
        )
        assert_that(result, equal_to(1))

        result = self._group_dao.count_users(
            group,
            filtered=True,
            search='example.com',
        )
        assert_that(result, equal_to(1))

    @fixtures.db.tenant(uuid=TENANT_UUID)
    @fixtures.db.group(name='foobar', tenant_uuid=TENANT_UUID)
    def test_create(self, tenant_uuid, group_uuid):
        name = 'foobar'
        slug = 'myslug'

        assert_that(group_uuid, equal_to(ANY_UUID))
        filter_ = models.Group.uuid == group_uuid
        group = self.session.query(models.Group).filter(filter_).first()
        assert_that(group, has_properties(name=name, tenant_uuid=tenant_uuid))

        assert_that(
            calling(self._group_dao.create).with_args(
                name, slug, tenant_uuid, system_managed=False
            ),
            raises(exceptions.DuplicateGroupException),
        )

    @fixtures.db.group()
    def test_delete(self, group_uuid):
        self._group_dao.delete(group_uuid)

        assert_that(
            calling(self._group_dao.delete).with_args(group_uuid),
            raises(exceptions.UnknownGroupException),
        )

    @fixtures.db.user()
    @fixtures.db.user()
    @fixtures.db.group(name='foo')
    @fixtures.db.group(name='bar')
    @fixtures.db.group(name='baz')
    def test_list(self, user1_uuid, user2_uuid, *group_uuids):
        def build_list_matcher(*names):
            return [has_entries(name=name) for name in names]

        result = self._group_dao.list_()
        expected = build_list_matcher('foo', 'bar', 'baz')
        assert_that(result, contains_inanyorder(*expected))

        for group_uuid in group_uuids:
            self._group_dao.add_user(group_uuid, user1_uuid)
            self._group_dao.add_user(group_uuid, user2_uuid)

        result = self._group_dao.list_()
        expected = build_list_matcher('foo', 'bar', 'baz')
        assert_that(result, contains_inanyorder(*expected))

        result = self._group_dao.list_(name='foo')
        expected = build_list_matcher('foo')
        assert_that(result, contains_inanyorder(*expected))

        result = self._group_dao.list_(search='ba')
        expected = build_list_matcher('bar', 'baz')
        assert_that(result, contains_inanyorder(*expected))

        result = self._group_dao.list_(order='name', direction='desc')
        expected = build_list_matcher('foo', 'baz', 'bar')
        assert_that(result, contains_exactly(*expected))

        result = self._group_dao.list_(order='name', direction='asc', limit=2)
        expected = build_list_matcher('bar', 'baz')
        assert_that(result, contains_exactly(*expected))

        result = self._group_dao.list_(order='name', direction='asc', offset=1)
        expected = build_list_matcher('baz', 'foo')
        assert_that(result, contains_exactly(*expected))

    @fixtures.db.group()
    @fixtures.db.policy()
    def test_remove_policy(self, group_uuid, policy_uuid):
        nb_deleted = self._group_dao.remove_policy(group_uuid, policy_uuid)
        assert_that(nb_deleted, equal_to(0))

        self._group_dao.add_policy(group_uuid, policy_uuid)

        nb_deleted = self._group_dao.remove_policy(self.unknown_uuid, policy_uuid)
        assert_that(nb_deleted, equal_to(0))

        nb_deleted = self._group_dao.remove_policy(group_uuid, self.unknown_uuid)
        assert_that(nb_deleted, equal_to(0))

        nb_deleted = self._group_dao.remove_policy(group_uuid, policy_uuid)
        assert_that(nb_deleted, equal_to(1))

    @fixtures.db.user()
    @fixtures.db.group()
    def test_remove_user(self, user_uuid, group_uuid):
        nb_deleted = self._group_dao.remove_user(group_uuid, user_uuid)
        assert_that(nb_deleted, equal_to(0))

        self._group_dao.add_user(group_uuid, user_uuid)

        nb_deleted = self._group_dao.remove_user(self.unknown_uuid, user_uuid)
        assert_that(nb_deleted, equal_to(0))

        nb_deleted = self._group_dao.remove_user(group_uuid, self.unknown_uuid)
        assert_that(nb_deleted, equal_to(0))

        nb_deleted = self._group_dao.remove_user(group_uuid, user_uuid)
        assert_that(nb_deleted, equal_to(1))

    @fixtures.db.tenant()
    @fixtures.db.group(name='foobar')
    def test_that_two_groups_cannot_have_the_same_name_and_tenant(
        self, tenant_uuid, group_uuid
    ):
        # Same name different tenants no exception
        assert_that(
            calling(self.create_and_delete_group).with_args(
                'foobar', tenant_uuid=tenant_uuid
            ),
            not_(raises(exceptions.DuplicateGroupException)),
        )

        # Same tenant different names no exception
        assert_that(
            calling(self.create_and_delete_group).with_args('foobaz'),
            not_(raises(exceptions.DuplicateGroupException)),
        )

        # Same name same tenant
        assert_that(
            calling(self.create_and_delete_group).with_args('foobar'),
            raises(exceptions.DuplicateGroupException),
        )

    @fixtures.db.tenant()
    @fixtures.db.group(slug='foobar')
    def test_that_two_groups_cannot_have_the_same_slug_and_tenant(
        self, tenant_uuid, group_uuid
    ):
        # Same slug different tenants no exception
        assert_that(
            calling(self.create_and_delete_group).with_args(
                'foobar', slug='foobar', tenant_uuid=tenant_uuid
            ),
            not_(raises(exceptions.DuplicateGroupException)),
        )

        # Same tenant different slug no exception
        assert_that(
            calling(self.create_and_delete_group).with_args('foobaz', slug='foobaz'),
            not_(raises(exceptions.DuplicateGroupException)),
        )

        # Same name same tenant
        assert_that(
            calling(self.create_and_delete_group).with_args('foobar', slug='foobar'),
            raises(exceptions.DuplicateGroupException),
        )

        # Same name case insensitive same tenant
        assert_that(
            calling(self.create_and_delete_group).with_args('fooBAR', slug='fooBAR'),
            raises(exceptions.DuplicateGroupException),
        )

    def test_group_creation_auto_generates_slug(self):
        name = 'group-name'
        with self._new_group(name=name, slug=None) as group_uuid:
            group = self._group_dao.find_by(uuid=group_uuid)
            assert_that(group, has_properties(slug=name))

    @fixtures.db.group(slug='foobar')
    @fixtures.db.group(slug='foobaz')
    @fixtures.db.group(slug='foobarbaz')
    def test_group_find_all_by_multiple_slug(self, g1_uuid, g2_uuid, g3_uuid):
        result = self._group_dao.find_all_by(slug=['foobar', 'foobarbaz'])
        assert_that(
            result,
            contains_inanyorder(
                has_properties(uuid=g1_uuid, slug='foobar'),
                has_properties(uuid=g3_uuid, slug='foobarbaz'),
            ),
        )

    @contextmanager
    def _new_group(self, name, slug=None, description=None, acl=None, tenant_uuid=None):
        tenant_uuid = tenant_uuid or self.top_tenant_uuid
        acl = acl or []
        slug = slug or name
        uuid_ = self._group_dao.create(
            name=name,
            slug=slug,
            tenant_uuid=tenant_uuid,
            system_managed=False,
        )
        try:
            yield uuid_
        finally:
            self._group_dao.delete(uuid_, [tenant_uuid])

    def create_and_delete_group(self, *args, **kwargs):
        with self._new_group(*args, **kwargs):
            pass
