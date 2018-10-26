# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from contextlib import (
    contextmanager,
    nested,
)
from hamcrest import (
    assert_that,
    calling,
    contains,
    contains_inanyorder,
    empty,
    equal_to,
    has_entries,
    not_,
)
from xivo_test_helpers.hamcrest.raises import raises
from wazo_auth import exceptions
from .helpers import fixtures, base


def setup():
    base.DBStarter.setUpClass()


def teardown():
    base.DBStarter.tearDownClass()


class TestPolicyDAO(base.DAOTestCase):

    def setUp(self):
        super(TestPolicyDAO, self).setUp()
        default_master_user_policy = self._policy_dao.get(name='wazo_default_master_user_policy')[0]
        default_user_policy = self._policy_dao.get(name='wazo_default_user_policy')[0]
        default_admin_policy = self._policy_dao.get(name='wazo_default_admin_policy')[0]
        self._default_master_user_policy_uuid = default_master_user_policy['uuid']
        self._default_user_policy_uuid = default_user_policy['uuid']
        self._default_admin_policy_uuid = default_admin_policy['uuid']

    @fixtures.policy(name='testé', description='déscription')
    def test_template_association(self, uuid):
        self._policy_dao.associate_policy_template(uuid, '#')
        assert_that(
            self.get_policy(uuid),
            has_entries(acl_templates=contains_inanyorder('#')),
        )

        assert_that(
            calling(self._policy_dao.associate_policy_template).with_args(uuid, '#'),
            raises(exceptions.DuplicateTemplateException),
        )

        self._policy_dao.dissociate_policy_template(uuid, '#')
        assert_that(
            self.get_policy(uuid),
            has_entries(acl_templates=empty()),
        )

        assert_that(
            calling(self._policy_dao.associate_policy_template).with_args('unknown', '#'),
            raises(exceptions.UnknownPolicyException),
        )

        assert_that(self._policy_dao.dissociate_policy_template('unknown', '#'), equal_to(0))

    @fixtures.tenant()
    def test_create(self, tenant_uuid):
        acl_templates = ['dird.#', 'confd.line.42.*']
        with self._new_policy('testé', 'descriptioñ', acl_templates, tenant_uuid) as uuid_:
            policy = self.get_policy(uuid_)

            assert_that(
                policy,
                has_entries(
                    uuid=uuid_,
                    name='testé',
                    description='descriptioñ',
                    acl_templates=contains_inanyorder(*acl_templates),
                    tenant_uuid=tenant_uuid,
                )
            )

    @fixtures.tenant()
    @fixtures.policy(name='foobar')
    def test_that_two_policies_cannot_have_the_same_name_and_tenant(self, policy_uuid, tenant_uuid):
        # Same name different tenants no exception
        assert_that(
            calling(self.create_and_delete_policy).with_args('foobar', '', tenant_uuid=tenant_uuid),
            not_(raises(exceptions.DuplicatePolicyException)),
        )

        # Same tenant different names no exception
        assert_that(
            calling(self.create_and_delete_policy).with_args('foobaz', ''),
            not_(raises(exceptions.DuplicatePolicyException)),
        )

        # Same name same tenant
        assert_that(
            calling(self.create_and_delete_policy).with_args('foobar', ''),
            raises(exceptions.DuplicatePolicyException),
        )

    @fixtures.policy(name='foobar')
    def test_get(self, uuid_):
        policy = self.get_policy(uuid_)
        assert_that(
            policy,
            has_entries(
                uuid=uuid_,
                name='foobar',
                description='',
                acl_templates=empty(),
            )
        )

        result = self._policy_dao.get(uuid=base.UNKNOWN_UUID)
        assert_that(result, empty())

    def test_get_sort_and_pagination(self):
        with nested(
            self._new_policy('a', 'z'),
            self._new_policy('b', 'y'),
            self._new_policy('c', 'x'),
        ) as (a, b, c):
            result = self.list_policy(order='name', direction='asc')
            assert_that(
                result,
                contains(
                    a,
                    b,
                    c,
                    self._default_admin_policy_uuid,
                    self._default_master_user_policy_uuid,
                    self._default_user_policy_uuid))

            result = self.list_policy(order='name', direction='desc')
            assert_that(
                result,
                contains(
                    self._default_user_policy_uuid,
                    self._default_master_user_policy_uuid,
                    self._default_admin_policy_uuid,
                    c,
                    b,
                    a))

            result = self.list_policy(order='description', direction='asc')
            assert_that(
                result,
                contains(
                    self._default_admin_policy_uuid,
                    self._default_master_user_policy_uuid,
                    self._default_user_policy_uuid,
                    c,
                    b,
                    a))

            result = self.list_policy(order='description', direction='desc')
            assert_that(
                result,
                contains(
                    a,
                    b,
                    c,
                    self._default_user_policy_uuid,
                    self._default_master_user_policy_uuid,
                    self._default_admin_policy_uuid))

            assert_that(
                calling(self.list_policy).with_args(order='foobar', direction='asc'),
                raises(exceptions.InvalidSortColumnException))

            assert_that(
                calling(self.list_policy).with_args(order='name', direction='down'),
                raises(exceptions.InvalidSortDirectionException))

            result = self.list_policy(order='name', direction='asc', limit=2)
            assert_that(result, contains(a, b))

            result = self.list_policy(order='name', direction='asc', offset=1)
            assert_that(
                result,
                contains(
                    b,
                    c,
                    self._default_admin_policy_uuid,
                    self._default_master_user_policy_uuid,
                    self._default_user_policy_uuid))

            invalid_offsets = [-1, 'two', True, False]
            for offset in invalid_offsets:
                assert_that(
                    calling(self.list_policy).with_args(order='name', direction='asc', offset=offset),
                    raises(exceptions.InvalidOffsetException),
                    offset)

            invalid_limits = [-1, 'two', True, False]
            for limit in invalid_limits:
                assert_that(
                    calling(self.list_policy).with_args(order='name', direction='asc', limit=limit),
                    raises(exceptions.InvalidLimitException),
                    limit)

    @fixtures.policy(name='c', description='The third foobar')
    @fixtures.policy(name='b', description='The second foobar')
    @fixtures.policy(name='a')
    @fixtures.user()
    def test_user_list_policies(self, user_uuid, policy_a, policy_b, policy_c):
        result = self._policy_dao.get(user_uuid=user_uuid)
        assert_that(result, empty(), 'empty')

        self._user_dao.add_policy(user_uuid, policy_a)
        self._user_dao.add_policy(user_uuid, policy_b)
        self._user_dao.add_policy(user_uuid, policy_c)

        result = self._policy_dao.get(user_uuid=user_uuid)
        assert_that(
            result,
            contains_inanyorder(
                has_entries('name', 'a'),
                has_entries('name', 'b'),
                has_entries('name', 'c'),
            ),
        )

    @fixtures.policy()
    def test_delete(self, uuid):
        assert_that(
            calling(self._policy_dao.delete).with_args(uuid, [self.top_tenant_uuid]),
            not_(raises(Exception)),
        )

        assert_that(
            calling(self._policy_dao.delete).with_args(base.UNKNOWN_UUID, [self.top_tenant_uuid]),
            raises(exceptions.UnknownPolicyException),
        )

    def test_update(self):
        assert_that(
            calling(self._policy_dao.update).with_args(base.UNKNOWN_UUID, 'foo', '', []),
            raises(exceptions.UnknownPolicyException),
        )

        with self._new_policy('foobar',
                              'This is the description',
                              ['confd.line.{{ line_id }}', 'dird.#']) as uuid_:
            self._policy_dao.update(
                uuid_, 'foobaz', 'A new description',
                ['confd.line.{{ line_id }}', 'dird.#', 'ctid-ng.#'])
            policy = self.get_policy(uuid_)

        assert_that(
            policy,
            has_entries(
                uuid=uuid_,
                name='foobaz',
                description='A new description',
                acl_templates=contains_inanyorder('confd.line.{{ line_id }}', 'dird.#', 'ctid-ng.#'),
            )
        )

    def get_policy(self, policy_uuid):
        for policy in self._policy_dao.get(uuid=policy_uuid, order='name', direction='asc'):
            return policy

    def list_policy(self, order=None, direction=None, limit=None, offset=None):
        policies = self._policy_dao.get(order=order, direction=direction, limit=limit, offset=offset)
        return [policy['uuid'] for policy in policies]

    @contextmanager
    def _new_policy(self, name, description, acl_templates=None, tenant_uuid=None):
        tenant_uuid = tenant_uuid or self.top_tenant_uuid
        acl_templates = acl_templates or []
        uuid_ = self._policy_dao.create(name, description, acl_templates, tenant_uuid)
        try:
            yield uuid_
        finally:
            self._policy_dao.delete(uuid_, [tenant_uuid])

    def create_and_delete_policy(self, *args, **kwargs):
        with self._new_policy(*args, **kwargs):
            pass
