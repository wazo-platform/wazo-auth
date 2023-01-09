# Copyright 2016-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import uuid

from hamcrest import (
    assert_that,
    calling,
    contains_exactly,
    contains_inanyorder,
    equal_to,
    has_entries,
    has_length,
    has_properties,
)
from wazo_test_helpers.hamcrest.raises import raises

from wazo_auth import exceptions
from wazo_auth.database import models
from .helpers import fixtures, base

SESSION_UUID_1 = str(uuid.uuid4())
USER_UUID_1 = str(uuid.uuid4())
USER_UUID_2 = str(uuid.uuid4())


@base.use_asset('database')
class TestExternalAuthDAO(base.DAOTestCase):

    auth_type = 'foobarcrm'
    data = {
        'string_value': 'an_important_value',
        'list_value': ['a', 'list', 'of', 'values'],
        'dict_value': {'a': 'dict', 'of': 'values'},
    }

    @fixtures.db.user()
    @fixtures.db.user()
    @fixtures.db.external_auth('one', 'two')
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

        result = self._external_auth_dao.count(
            user_1_uuid, search='two', filtered=False
        )
        assert_that(result, equal_to(2))
        result = self._external_auth_dao.count(user_1_uuid, search='two', filtered=True)
        assert_that(result, equal_to(1))

        result = self._external_auth_dao.count(user_1_uuid, type='two', filtered=False)
        assert_that(result, equal_to(2))
        result = self._external_auth_dao.count(user_1_uuid, type='two', filtered=True)
        assert_that(result, equal_to(1))

    @fixtures.db.user(uuid=USER_UUID_1)
    @fixtures.db.user(uuid=USER_UUID_2)
    @fixtures.db.external_auth('foobarcrm')
    def test_count_connected_users(self, user1_uuid, user2_uuid, *_):
        self._external_auth_dao.create(user1_uuid, 'foobarcrm', 'some-data')

        result = self._external_auth_dao.count_connected_users('foobarcrm')
        assert_that(result, equal_to(1))

        self._external_auth_dao.create(user2_uuid, 'foobarcrm', 'some-other-data')
        result = self._external_auth_dao.count_connected_users('foobarcrm')
        assert_that(result, equal_to(2))

    @fixtures.db.user()
    def test_create(self, user_uuid):
        assert_that(
            calling(self._external_auth_dao.create).with_args(
                self.unknown_uuid, self.auth_type, self.data
            ),
            raises(exceptions.UnknownUserException).matching(
                has_properties(status_code=404, resource='users')
            ),
        )

        result = self._external_auth_dao.create(user_uuid, self.auth_type, self.data)
        assert_that(result, equal_to(self.data))

        assert_that(
            self._external_auth_dao.get(user_uuid, self.auth_type), equal_to(self.data)
        )

        assert_that(
            calling(self._external_auth_dao.create).with_args(
                user_uuid, self.auth_type, self.data
            ),
            raises(exceptions.ExternalAuthAlreadyExists).matching(
                has_properties(
                    status_code=409,
                    resource=self.auth_type,
                    details=has_entries('type', self.auth_type),
                )
            ),
        )

    @fixtures.db.user()
    @fixtures.db.user()
    @fixtures.db.external_auth('foobarcrm')
    def test_delete(self, user_1_uuid, user_2_uuid, _):
        assert_that(
            calling(self._external_auth_dao.delete).with_args(
                self.unknown_uuid, self.auth_type
            ),
            raises(exceptions.UnknownUserException).matching(
                has_properties(status_code=404, resource='users')
            ),
        )

        assert_that(
            calling(self._external_auth_dao.delete).with_args(
                user_1_uuid, 'the_unknown_service'
            ),
            raises(exceptions.UnknownExternalAuthTypeException).matching(
                has_properties(status_code=404, resource='external')
            ),
        )

        # This will create the type in the db
        self._external_auth_dao.create(user_2_uuid, self.auth_type, self.data)

        assert_that(
            calling(self._external_auth_dao.delete).with_args(
                user_1_uuid, self.auth_type
            ),
            raises(exceptions.UnknownExternalAuthException).matching(
                has_properties(status_code=404, resource=self.auth_type)
            ),
        )

        self._external_auth_dao.create(user_1_uuid, self.auth_type, self.data)

        base.assert_no_error(
            self._external_auth_dao.delete, user_1_uuid, self.auth_type
        )

        assert_that(
            calling(self._external_auth_dao.delete).with_args(
                user_1_uuid, self.auth_type
            ),
            raises(exceptions.UnknownExternalAuthException).matching(
                has_properties(status_code=404, resource=self.auth_type)
            ),
        )

    @fixtures.db.user()
    def test_enable_all(self, user_uuid):
        def assert_enabled(enabled_types):
            query = self.session.query(
                models.ExternalAuthType.name, models.ExternalAuthType.enabled
            )
            result = {r.name: r.enabled for r in query.all()}
            expected = has_entries({t: True for t in enabled_types})
            assert_that(result, expected)
            nb_enabled = len([t for t, enabled in result.items() if enabled])
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

    @fixtures.db.user()
    @fixtures.db.user()
    @fixtures.db.external_auth('foobarcrm')
    def test_get(self, user_1_uuid, user_2_uuid, _):
        assert_that(
            calling(self._external_auth_dao.get).with_args(
                self.unknown_uuid, self.auth_type
            ),
            raises(exceptions.UnknownUserException).matching(
                has_properties(status_code=404, resource='users')
            ),
        )

        assert_that(
            calling(self._external_auth_dao.get).with_args(
                user_1_uuid, 'the_unknown_service'
            ),
            raises(exceptions.UnknownExternalAuthTypeException).matching(
                has_properties(status_code=404, resource='external')
            ),
        )

        assert_that(
            calling(self._external_auth_dao.get).with_args(user_1_uuid, self.auth_type),
            raises(exceptions.UnknownExternalAuthException).matching(
                has_properties(status_code=404, resource=self.auth_type)
            ),
        )

        self._external_auth_dao.create(user_1_uuid, self.auth_type, self.data)

        result = self._external_auth_dao.get(user_1_uuid, self.auth_type)
        assert_that(result, equal_to(self.data))

        assert_that(
            calling(self._external_auth_dao.get).with_args(user_2_uuid, self.auth_type),
            raises(exceptions.UnknownExternalAuthException).matching(
                has_properties(status_code=404, resource=self.auth_type)
            ),
        )

    @fixtures.db.user()
    @fixtures.db.user()
    @fixtures.db.external_auth('one', 'two', 'unused')
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
        expected = [{'type': 'two', 'data': data_two, 'enabled': True}]
        assert_that(result, contains_inanyorder(*expected))

        result = self._external_auth_dao.list_(user_1_uuid, type='two')
        expected = [{'type': 'two', 'data': data_two, 'enabled': True}]
        assert_that(result, contains_inanyorder(*expected))

        result = self._external_auth_dao.list_(
            user_1_uuid, order='type', direction='desc'
        )
        expected = [
            {'type': 'unused', 'data': {}, 'enabled': False},
            {'type': 'two', 'data': data_two, 'enabled': True},
            {'type': 'one', 'data': data_one, 'enabled': True},
        ]
        assert_that(result, contains_exactly(*expected))

        result = self._external_auth_dao.list_(
            user_1_uuid, order='type', direction='asc', limit=1
        )
        expected = [{'type': 'one', 'data': data_one, 'enabled': True}]
        assert_that(result, contains_exactly(*expected))

    @fixtures.db.user(uuid=USER_UUID_1)
    @fixtures.db.user(uuid=USER_UUID_2)
    @fixtures.db.user()
    @fixtures.db.external_auth('foobarcrm')
    def test_list_connected_users(self, user1_uuid, user2_uuid, user3_uuid, *ignored):
        self._external_auth_dao.create(user1_uuid, 'foobarcrm', {})

        results = self._external_auth_dao.list_connected_users('foobarcrm')
        expected = [user1_uuid]
        assert_that(results, contains_inanyorder(*expected))

        self._external_auth_dao.create(user2_uuid, 'foobarcrm', {})
        results = self._external_auth_dao.list_connected_users('foobarcrm')
        expected = [user1_uuid, user2_uuid]
        assert_that(results, contains_inanyorder(*expected))

        self._external_auth_dao.create(user3_uuid, 'foobarcrm', {})
        results = self._external_auth_dao.list_connected_users('foobarcrm')
        expected = [user1_uuid, user2_uuid, user3_uuid]
        assert_that(results, contains_inanyorder(*expected))

        self._external_auth_dao.delete(user2_uuid, 'foobarcrm')
        results = self._external_auth_dao.list_connected_users('foobarcrm')
        expected = [user1_uuid, user3_uuid]
        assert_that(results, contains_inanyorder(*expected))

        results = self._external_auth_dao.list_connected_users('foobarcrm', limit=1)
        assert_that(results, has_length(1))

        results = self._external_auth_dao.list_connected_users('foobarcrm', offset=1)
        assert_that(results, has_length(1))

        assert_that(
            calling(self._external_auth_dao.list_connected_users).with_args(
                'the_unknown_service'
            ),
            raises(exceptions.UnknownExternalAuthTypeException).matching(
                has_properties(status_code=404, resource='external')
            ),
        )

    @fixtures.db.user()
    @fixtures.db.external_auth('foobarcrm')
    def test_update(self, user_uuid, _):
        new_data = {'foo': 'bar'}

        assert_that(
            calling(self._external_auth_dao.update).with_args(
                self.unknown_uuid, self.auth_type, new_data
            ),
            raises(exceptions.UnknownUserException).matching(
                has_properties(status_code=404, resource='users')
            ),
        )

        assert_that(
            calling(self._external_auth_dao.update).with_args(
                user_uuid, 'the_unknown_service', new_data
            ),
            raises(exceptions.UnknownExternalAuthTypeException).matching(
                has_properties(status_code=404, resource='external')
            ),
        )

        assert_that(
            calling(self._external_auth_dao.update).with_args(
                user_uuid, self.auth_type, new_data
            ),
            raises(exceptions.UnknownExternalAuthException).matching(
                has_properties(status_code=404, resource=self.auth_type)
            ),
        )

        self._external_auth_dao.create(user_uuid, self.auth_type, self.data)

        result = self._external_auth_dao.update(user_uuid, self.auth_type, new_data)
        assert_that(result, equal_to(new_data))
        assert_that(
            self._external_auth_dao.get(user_uuid, self.auth_type), equal_to(new_data)
        )
