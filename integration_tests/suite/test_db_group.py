# Copyright 2016-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import (
    assert_that,
    calling,
    contains,
    contains_inanyorder,
    empty,
    equal_to,
    has_entries,
    has_key,
    has_properties,
)
from xivo_test_helpers.mock import ANY_UUID
from xivo_test_helpers.hamcrest.raises import raises

from wazo_auth import exceptions
from wazo_auth.database import models
from .helpers import fixtures, base


TENANT_UUID = 'a26c4ed8-767f-463e-a10a-42c4f220d375'


def setup_module():
    base.DBStarter.setUpClass()


def teardown_module():
    base.DBStarter.tearDownClass()


class TestGroupDAO(base.DAOTestCase):
    @fixtures.db.policy()
    @fixtures.db.group()
    def test_add_policy(self, group_uuid, policy_uuid):
        assert_that(self._policy_dao.get(group_uuid=group_uuid), empty())

        self._group_dao.add_policy(group_uuid, policy_uuid)
        result = self._policy_dao.get(group_uuid=group_uuid)
        assert_that(result, contains(has_entries(uuid=policy_uuid)))

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

    @fixtures.db.user()
    @fixtures.db.group()
    def test_add_user(self, group_uuid, user_uuid):
        assert_that(self._user_dao.list_(group_uuid=group_uuid), empty())

        self._group_dao.add_user(group_uuid, user_uuid)
        result = self._user_dao.list_(group_uuid=group_uuid)
        assert_that(result, contains(has_entries(uuid=user_uuid)))

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

    @fixtures.db.tenant(uuid=TENANT_UUID)
    @fixtures.db.group(name='foobar', tenant_uuid=TENANT_UUID)
    def test_create(self, group_uuid, tenant_uuid):
        name = 'foobar'

        assert_that(group_uuid, equal_to(ANY_UUID))
        with self._group_dao.new_session() as s:
            filter_ = models.Group.uuid == group_uuid
            group = s.query(models.Group).filter(filter_).first()
            assert_that(group, has_properties(name=name, tenant_uuid=tenant_uuid))

        assert_that(
            calling(self._group_dao.create).with_args(name, tenant_uuid),
            raises(exceptions.ConflictException).matching(
                has_properties(
                    'status_code', 409, 'resource', 'groups', 'details', has_key('name')
                )
            ),
        )

    @fixtures.db.group()
    def test_delete(self, group_uuid):
        self._group_dao.delete(group_uuid)

        assert_that(
            calling(self._group_dao.delete).with_args(group_uuid),
            raises(exceptions.UnknownGroupException),
        )

    @fixtures.db.group(name='foo')
    @fixtures.db.group(name='bar')
    @fixtures.db.group(name='baz')
    @fixtures.db.user()
    @fixtures.db.user()
    def test_list(self, user1_uuid, user2_uuid, *group_uuids):
        def build_list_matcher(*names):
            return [has_entries('name', name) for name in names]

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
        assert_that(result, contains(*expected))

        result = self._group_dao.list_(order='name', direction='asc', limit=2)
        expected = build_list_matcher('bar', 'baz')
        assert_that(result, contains(*expected))

        result = self._group_dao.list_(order='name', direction='asc', offset=1)
        expected = build_list_matcher('baz', 'foo')
        assert_that(result, contains(*expected))

    @fixtures.db.group()
    @fixtures.db.policy()
    def test_remove_policy(self, policy_uuid, group_uuid):
        nb_deleted = self._group_dao.remove_policy(group_uuid, policy_uuid)
        assert_that(nb_deleted, equal_to(0))

        self._group_dao.add_policy(group_uuid, policy_uuid)

        nb_deleted = self._group_dao.remove_policy(self.unknown_uuid, policy_uuid)
        assert_that(nb_deleted, equal_to(0))

        nb_deleted = self._group_dao.remove_policy(group_uuid, self.unknown_uuid)
        assert_that(nb_deleted, equal_to(0))

        nb_deleted = self._group_dao.remove_policy(group_uuid, policy_uuid)
        assert_that(nb_deleted, equal_to(1))

    @fixtures.db.group()
    @fixtures.db.user()
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
