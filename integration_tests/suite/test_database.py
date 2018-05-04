# -*- coding: utf-8 -*-
# Copyright 2016-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import time
import uuid

from contextlib import contextmanager, nested
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
    instance_of,
    not_,
)
from xivo_test_helpers.mock import ANY_UUID
from xivo_test_helpers.hamcrest.raises import raises

from wazo_auth import exceptions
from wazo_auth.database import models
from .helpers import fixtures, base


def new_uuid():
    return str(uuid.uuid4())


def setup():
    base.DBStarter.setUpClass()


def teardown():
    base.DBStarter.tearDownClass()


class TestAddressDAO(base.DAOTestCase):

    def setUp(self):
        super(TestAddressDAO, self).setUp()
        self._null_address = self._address()

    def test_new_address(self):
        result = self._address_dao.new(**self._null_address)
        assert_that(result, equal_to(None))

        address = self._address(line_1='here')
        result = self._address_dao.new(**address)
        assert_that(result, instance_of(int))

    def test_update(self):
        address = self._address(line_1='here')
        address_id = self._address_dao.new(**address)

        updated_address = self._address(line_1='here', country='Canada')
        result = self._address_dao.update(address_id, **updated_address)
        assert_that(result, equal_to(address_id))
        assert_that(self._address_dao.get(address_id), equal_to(updated_address))

        result = self._address_dao.update(address_id, **self._null_address)
        assert_that(result, equal_to(None))
        assert_that(calling(self._address_dao.get).with_args(address_id), raises(Exception))

    @staticmethod
    def _address(line_1=None, line_2=None, city=None, state=None, country=None, zip_code=None):
        return {
            'line_1': line_1,
            'line_2': line_2,
            'city': city,
            'state': state,
            'country': country,
            'zip_code': zip_code,
        }


class TestEmailDAO(base.DAOTestCase):

    @fixtures.email()
    def test_confirm(self, email_uuid):
        assert_that(self.is_email_confirmed(email_uuid), equal_to(False))
        assert_that(
            calling(self._email_dao.confirm).with_args(base.UNKNOWN_UUID),
            raises(exceptions.UnknownEmailException))
        self._email_dao.confirm(email_uuid)
        assert_that(self.is_email_confirmed(email_uuid), equal_to(True))

    def is_email_confirmed(self, email_uuid):
        with self._email_dao.new_session() as s:
            emails = s.query(models.Email).filter(models.Email.uuid == str(email_uuid))
            for email in emails.all():
                return email.confirmed
        return False


class TestExternalAuthDAO(base.DAOTestCase):

    auth_type = 'foobarcrm'
    data = {
        'string_value': 'an_important_value',
        'list_value': ['a', 'list', 'of', 'values'],
        'dict_value': {'a': 'dict', 'of': 'values'},
    }

    @fixtures.external_auth('one', 'two')
    @fixtures.user()
    @fixtures.user()
    def test_count(self, user_1_uuid, user_2_uuid, external_auth_types):
        self._external_auth_dao.create(user_2_uuid, self.auth_type, self.data)

        result = self._external_auth_dao.count(user_1_uuid, filtered=False)
        assert_that(result, equal_to(2))

        result = self._external_auth_dao.count(user_1_uuid, filtered=True)
        assert_that(result, equal_to(2))

        data_one = {'username': 'foo', 'password': 'baz'}
        data_two = {'key': 'foo', 'secret': 'bar'}
        self._external_auth_dao.create(user_1_uuid, 'one', data_one)
        self._external_auth_dao.create(user_1_uuid, 'two', data_two)

        result = self._external_auth_dao.count(user_1_uuid, filtered=False)
        assert_that(result, equal_to(2))
        result = self._external_auth_dao.count(user_1_uuid, filtered=True)
        assert_that(result, equal_to(2))

        result = self._external_auth_dao.count(user_1_uuid, search='two', filtered=False)
        assert_that(result, equal_to(2))
        result = self._external_auth_dao.count(user_1_uuid, search='two', filtered=True)
        assert_that(result, equal_to(1))

        result = self._external_auth_dao.count(user_1_uuid, type='two', filtered=False)
        assert_that(result, equal_to(2))
        result = self._external_auth_dao.count(user_1_uuid, type='two', filtered=True)
        assert_that(result, equal_to(1))

    @fixtures.user()
    def test_create(self, user_uuid):
        assert_that(
            calling(self._external_auth_dao.create).with_args(self.unknown_uuid, self.auth_type, self.data),
            raises(exceptions.UnknownUserException).matching(
                has_properties(
                    status_code=404,
                    resource='users')))

        result = self._external_auth_dao.create(user_uuid, self.auth_type, self.data)
        assert_that(result, equal_to(self.data))

        assert_that(
            self._external_auth_dao.get(user_uuid, self.auth_type),
            equal_to(self.data))

        assert_that(
            calling(self._external_auth_dao.create).with_args(user_uuid, self.auth_type, self.data),
            raises(exceptions.ExternalAuthAlreadyExists).matching(
                has_properties(
                    status_code=409,
                    resource=self.auth_type,
                    details=has_entries('type', self.auth_type))))

    @fixtures.user()
    @fixtures.user()
    def test_delete(self, user_1_uuid, user_2_uuid):
        assert_that(
            calling(self._external_auth_dao.delete).with_args(self.unknown_uuid, self.auth_type),
            raises(exceptions.UnknownUserException).matching(
                has_properties(status_code=404, resource='users')))

        assert_that(
            calling(self._external_auth_dao.delete).with_args(user_1_uuid, 'the_unknown_service'),
            raises(exceptions.UnknownExternalAuthTypeException).matching(
                has_properties(status_code=404, resource='external')))

        # This will create the type in the db
        self._external_auth_dao.create(user_2_uuid, self.auth_type, self.data)

        assert_that(
            calling(self._external_auth_dao.delete).with_args(user_1_uuid, self.auth_type),
            raises(exceptions.UnknownExternalAuthException).matching(
                has_properties(status_code=404, resource=self.auth_type)))

        self._external_auth_dao.create(user_1_uuid, self.auth_type, self.data)

        base.assert_no_error(self._external_auth_dao.delete, user_1_uuid, self.auth_type)

        assert_that(
            calling(self._external_auth_dao.delete).with_args(user_1_uuid, self.auth_type),
            raises(exceptions.UnknownExternalAuthException).matching(
                has_properties(status_code=404, resource=self.auth_type)))

    @fixtures.user()
    def test_enable_all(self, user_uuid):
        def assert_enabled(enabled_types):
            with self._external_auth_dao.new_session() as s:
                query = s.query(models.ExternalAuthType.name, models.ExternalAuthType.enabled)
                result = {r.name: r.enabled for r in query.all()}
            expected = has_entries({t: True for t in enabled_types})
            assert_that(result, expected)
            nb_enabled = len([t for t, enabled in result.iteritems() if enabled])
            assert_that(nb_enabled, equal_to(len(enabled_types)))

        auth_types = ['foo', 'bar', 'baz', 'inga']
        self._external_auth_dao.enable_all(auth_types)
        assert_enabled(auth_types)

        auth_types = ['one', 'two']
        self._external_auth_dao.enable_all(auth_types)
        assert_enabled(auth_types)

        auth_types = ['one', 'baz', 'foobar']
        self._external_auth_dao.enable_all(auth_types)
        assert_enabled(auth_types)

        auth_types = []
        self._external_auth_dao.enable_all(auth_types)
        assert_enabled(auth_types)

    @fixtures.user()
    @fixtures.user()
    def test_get(self, user_1_uuid, user_2_uuid):
        assert_that(
            calling(self._external_auth_dao.get).with_args(self.unknown_uuid, self.auth_type),
            raises(exceptions.UnknownUserException).matching(
                has_properties(status_code=404, resource='users')))

        assert_that(
            calling(self._external_auth_dao.get).with_args(user_1_uuid, 'the_unknown_service'),
            raises(exceptions.UnknownExternalAuthTypeException).matching(
                has_properties(status_code=404, resource='external')))

        assert_that(
            calling(self._external_auth_dao.get).with_args(user_1_uuid, self.auth_type),
            raises(exceptions.UnknownExternalAuthException).matching(
                has_properties(status_code=404, resource=self.auth_type)))

        self._external_auth_dao.create(user_1_uuid, self.auth_type, self.data)

        result = self._external_auth_dao.get(user_1_uuid, self.auth_type)
        assert_that(result, equal_to(self.data))

        assert_that(
            calling(self._external_auth_dao.get).with_args(user_2_uuid, self.auth_type),
            raises(exceptions.UnknownExternalAuthException).matching(
                has_properties(status_code=404, resource=self.auth_type)))

    @fixtures.external_auth('one', 'two', 'unused')
    @fixtures.user()
    @fixtures.user()
    def test_list(self, user_1_uuid, user_2_uuid, auth_types):
        self._external_auth_dao.create(user_2_uuid, self.auth_type, self.data)

        result = self._external_auth_dao.list_(user_1_uuid)
        expected = [
            {'type': 'one', 'data': {}, 'enabled': False},
            {'type': 'two', 'data': {}, 'enabled': False},
            {'type': 'unused', 'data': {}, 'enabled': False},
        ]
        assert_that(result, contains_inanyorder(*expected))

        data_one = {'username': 'foo', 'password': 'baz'}
        data_two = {'key': 'foo', 'secret': 'bar'}
        self._external_auth_dao.create(user_1_uuid, 'one', data_one)
        self._external_auth_dao.create(user_1_uuid, 'two', data_two)

        result = self._external_auth_dao.list_(user_1_uuid)
        expected = [
            {'type': 'one', 'data': data_one, 'enabled': True},
            {'type': 'two', 'data': data_two, 'enabled': True},
            {'type': 'unused', 'data': {}, 'enabled': False},
        ]
        assert_that(result, contains_inanyorder(*expected))

        result = self._external_auth_dao.list_(user_1_uuid, search='two')
        expected = [
            {'type': 'two', 'data': data_two, 'enabled': True},
        ]
        assert_that(result, contains_inanyorder(*expected))

        result = self._external_auth_dao.list_(user_1_uuid, type='two')
        expected = [
            {'type': 'two', 'data': data_two, 'enabled': True},
        ]
        assert_that(result, contains_inanyorder(*expected))

        result = self._external_auth_dao.list_(user_1_uuid, order='type', direction='desc')
        expected = [
            {'type': 'unused', 'data': {}, 'enabled': False},
            {'type': 'two', 'data': data_two, 'enabled': True},
            {'type': 'one', 'data': data_one, 'enabled': True},
        ]
        assert_that(result, contains(*expected))

        result = self._external_auth_dao.list_(user_1_uuid, order='type', direction='asc', limit=1)
        expected = [
            {'type': 'one', 'data': data_one, 'enabled': True},
        ]
        assert_that(result, contains(*expected))

    @fixtures.user()
    def test_update(self, user_uuid):
        new_data = {'foo': 'bar'}

        assert_that(
            calling(self._external_auth_dao.update).with_args(self.unknown_uuid, self.auth_type, new_data),
            raises(exceptions.UnknownUserException).matching(
                has_properties(status_code=404, resource='users')))

        assert_that(
            calling(self._external_auth_dao.update).with_args(user_uuid, 'the_unknown_service', new_data),
            raises(exceptions.UnknownExternalAuthTypeException).matching(
                has_properties(status_code=404, resource='external')))

        assert_that(
            calling(self._external_auth_dao.update).with_args(user_uuid, self.auth_type, new_data),
            raises(exceptions.UnknownExternalAuthException).matching(
                has_properties(status_code=404, resource=self.auth_type)))

        self._external_auth_dao.create(user_uuid, self.auth_type, self.data)

        result = self._external_auth_dao.update(user_uuid, self.auth_type, new_data)
        assert_that(result, equal_to(new_data))
        assert_that(self._external_auth_dao.get(user_uuid, self.auth_type), equal_to(new_data))


class TestGroupDAO(base.DAOTestCase):

    @fixtures.policy()
    @fixtures.group()
    def test_add_policy(self, group_uuid, policy_uuid):
        assert_that(self._policy_dao.get(group_uuid=group_uuid), empty())

        self._group_dao.add_policy(group_uuid, policy_uuid)
        assert_that(self._policy_dao.get(group_uuid=group_uuid), contains(has_entries('uuid', policy_uuid)))

        self._group_dao.add_policy(group_uuid, policy_uuid)  # twice

        assert_that(
            calling(self._group_dao.add_policy).with_args(self.unknown_uuid, policy_uuid),
            raises(exceptions.UnknownGroupException),
            'unknown group',
        )

        assert_that(
            calling(self._group_dao.add_policy).with_args(group_uuid, self.unknown_uuid),
            raises(exceptions.UnknownPolicyException),
            'unknown policy',
        )

    @fixtures.user()
    @fixtures.group()
    def test_add_user(self, group_uuid, user_uuid):
        assert_that(self._user_dao.list_(group_uuid=group_uuid), empty())

        self._group_dao.add_user(group_uuid, user_uuid)
        assert_that(self._user_dao.list_(group_uuid=group_uuid), contains(has_entries('uuid', user_uuid)))

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

    @fixtures.group(name='foo')
    @fixtures.group(name='bar')
    @fixtures.group(name='baz')
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

    @fixtures.group(name='foobar')
    def test_create(self, group_uuid):
        name = 'foobar'

        assert_that(group_uuid, equal_to(ANY_UUID))
        with self._group_dao.new_session() as s:
            filter_ = models.Group.uuid == group_uuid
            group = s.query(models.Group).filter(filter_).first()
            assert_that(group, has_properties('name', name))

        assert_that(
            calling(self._group_dao.create).with_args(name),
            raises(exceptions.ConflictException).matching(
                has_properties(
                    'status_code', 409,
                    'resource', 'groups',
                    'details', has_key('name'))))

    @fixtures.group()
    def test_delete(self, group_uuid):
        self._group_dao.delete(group_uuid)

        assert_that(
            calling(self._group_dao.delete).with_args(group_uuid),
            raises(exceptions.UnknownGroupException),
        )

    @fixtures.group(name='foo')
    @fixtures.group(name='bar')
    @fixtures.group(name='baz')
    @fixtures.user()
    @fixtures.user()
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

    @fixtures.group()
    @fixtures.policy()
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

    @fixtures.group()
    @fixtures.user()
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


class TestPolicyDAO(base.DAOTestCase):

    def setUp(self):
        super(TestPolicyDAO, self).setUp()
        default_master_user_policy = self._policy_dao.get(name='wazo_default_master_user_policy')[0]
        default_user_policy = self._policy_dao.get(name='wazo_default_user_policy')[0]
        default_admin_policy = self._policy_dao.get(name='wazo_default_admin_policy')[0]
        self._default_master_user_policy_uuid = default_master_user_policy['uuid']
        self._default_user_policy_uuid = default_user_policy['uuid']
        self._default_admin_policy_uuid = default_admin_policy['uuid']

    def test_template_association(self):
        assert_that(
            calling(self._policy_dao.associate_policy_template).with_args('unknown', '#'),
            raises(exceptions.UnknownPolicyException))

        assert_that(self._policy_dao.dissociate_policy_template('unknown', '#'), equal_to(0))

        with self._new_policy(u'testé', u'descriptioñ', []) as uuid_:
            self._policy_dao.associate_policy_template(uuid_, '#')
            policy = self.get_policy(uuid_)
            assert_that(policy['acl_templates'], contains_inanyorder('#'))

            assert_that(
                calling(self._policy_dao.associate_policy_template).with_args(uuid_, '#'),
                raises(exceptions.DuplicateTemplateException))

            self._policy_dao.dissociate_policy_template(uuid_, '#')
            policy = self.get_policy(uuid_)
            assert_that(policy['acl_templates'], empty())

    @fixtures.tenant()
    def test_create(self, tenant_uuid):
        acl_templates = ['dird.#', 'confd.line.42.*']
        with self._new_policy(u'testé', u'descriptioñ', acl_templates, tenant_uuid) as uuid_:
            policy = self.get_policy(uuid_)

            assert_that(policy['uuid'], equal_to(uuid_))
            assert_that(policy['name'], equal_to(u'testé'))
            assert_that(policy['description'], equal_to(u'descriptioñ'))
            assert_that(policy['acl_templates'], contains_inanyorder(*acl_templates))
            assert_that(policy['tenant_uuid'], equal_to(tenant_uuid))

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
        assert_that(policy, has_entries(
            'uuid', uuid_,
            'name', 'foobar',
            'description', '',
            'acl_templates', empty()))

        unknown_uuid = '00000000-0000-0000-0000-000000000000'
        result = self._policy_dao.get(uuid=unknown_uuid)
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

    def test_delete(self):
        uuid_ = self._policy_dao.create('foobar', '', [], self.top_tenant_uuid)
        self._policy_dao.delete(uuid_)
        assert_that(
            calling(self._policy_dao.delete).with_args(uuid_),
            raises(exceptions.UnknownPolicyException))

    def test_update(self):
        assert_that(
            calling(self._policy_dao.update).with_args('unknown', 'foo', '', []),
            raises(exceptions.UnknownPolicyException))

        with self._new_policy('foobar',
                              'This is the description',
                              ['confd.line.{{ line_id }}', 'dird.#']) as uuid_:
            self._policy_dao.update(
                uuid_, 'foobaz', 'A new description',
                ['confd.line.{{ line_id }}', 'dird.#', 'ctid-ng.#'])
            policy = self.get_policy(uuid_)

            assert_that(policy['uuid'], equal_to(uuid_))
            assert_that(policy['name'], equal_to('foobaz'))
            assert_that(policy['description'], equal_to('A new description'))
            assert_that(
                policy['acl_templates'],
                contains_inanyorder('confd.line.{{ line_id }}', 'dird.#', 'ctid-ng.#'))

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
            self._policy_dao.delete(uuid_)

    def create_and_delete_policy(self, *args, **kwargs):
        with self._new_policy(*args, **kwargs):
            pass


class TestTokenDAO(base.DAOTestCase):

    def test_create(self):
        metadata = {
            'uuid': '08b213da-9963-4d25-96a3-f02d717e82f2',
            'id': 42,
            'msg': 'a string field',
        }

        with nested(self._new_token(metadata=metadata),
                    self._new_token(acls=['first', 'second'])) as (e1, e2):
            assert_that(e1['metadata'], has_entries(**metadata))
            t1 = self._token_dao.get(e1['uuid'])
            t2 = self._token_dao.get(e2['uuid'])
            assert_that(t1, equal_to(e1))
            assert_that(t2, equal_to(e2))

    def test_get(self):
        self.assertRaises(exceptions.UnknownTokenException, self._token_dao.get,
                          'unknown')
        with nested(self._new_token(),
                    self._new_token(),
                    self._new_token()) as (_, expected_token, __):
            token = self._token_dao.get(expected_token['uuid'])
        assert_that(token, equal_to(expected_token))

    def test_delete(self):
        with self._new_token() as token:
            self._token_dao.delete(token['uuid'])
            self.assertRaises(exceptions.UnknownTokenException, self._token_dao.get,
                              token['uuid'])
            self._token_dao.delete(token['uuid'])  # No error on delete unknown

    def test_delete_expired_tokens(self):
        with nested(
                self._new_token(),
                self._new_token(expiration=0),
                self._new_token(expiration=0),
        ) as (a, b, c):
            expired = [b, c]
            valid = [a]

            self._token_dao.delete_expired_tokens()

            for token in valid:
                assert_that(calling(self._token_dao.get).with_args(token['uuid']),
                            not_(raises(exceptions.UnknownTokenException)))
            for token in expired:
                assert_that(calling(self._token_dao.get).with_args(token['uuid']),
                            raises(exceptions.UnknownTokenException))

    @contextmanager
    def _new_token(self, acls=None, metadata=None, expiration=120):
        now = int(time.time())
        body = {
            'auth_id': 'test',
            'xivo_user_uuid': new_uuid(),
            'xivo_uuid': new_uuid(),
            'issued_t': now,
            'expire_t': now + expiration,
            'acls': acls or [],
            'metadata': metadata or {},
        }
        token_uuid = self._token_dao.create(body)
        token_data = dict(body)
        token_data['uuid'] = token_uuid
        yield token_data
        self._token_dao.delete(token_uuid)
