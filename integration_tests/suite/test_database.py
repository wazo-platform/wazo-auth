# Copyright 2016-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import time
import uuid

from contextlib import contextmanager
from hamcrest import (
    assert_that,
    calling,
    contains,
    contains_inanyorder,
    equal_to,
    has_entries,
    has_properties,
    instance_of,
    not_,
)
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
        super().setUp()
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


class TestTokenDAO(base.DAOTestCase):

    def test_create(self):
        metadata = {
            'uuid': '08b213da-9963-4d25-96a3-f02d717e82f2',
            'id': 42,
            'msg': 'a string field',
        }

        with self._new_token(metadata=metadata) as e1, \
                self._new_token(acls=['first', 'second']) as e2:
            assert_that(e1['metadata'], has_entries(**metadata))
            t1 = self._token_dao.get(e1['uuid'])
            t2 = self._token_dao.get(e2['uuid'])
            assert_that(t1, equal_to(e1))
            assert_that(t2, equal_to(e2))

    def test_get(self):
        self.assertRaises(exceptions.UnknownTokenException, self._token_dao.get,
                          'unknown')
        with self._new_token(), self._new_token() as expected_token, self._new_token():
            token = self._token_dao.get(expected_token['uuid'])
        assert_that(token, equal_to(expected_token))

    def test_delete(self):
        with self._new_token() as token:
            self._token_dao.delete(token['uuid'])
            self.assertRaises(exceptions.UnknownTokenException, self._token_dao.get,
                              token['uuid'])
            self._token_dao.delete(token['uuid'])  # No error on delete unknown

    def test_delete_expired_tokens(self):
        with self._new_token() as a, \
                self._new_token(expiration=0) as b, \
                self._new_token(expiration=0) as c:
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
