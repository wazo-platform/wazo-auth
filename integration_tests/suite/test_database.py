# -*- coding: utf-8 -*-
#
# Copyright 2016-2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>

import os
import time
import unittest
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
    has_properties,
    none,
    not_,
)
from mock import ANY
from xivo_test_helpers.asset_launching_test_case import AssetLaunchingTestCase
from xivo_test_helpers.mock import ANY_UUID
from xivo_test_helpers.hamcrest.raises import raises

from wazo_auth import database, exceptions
from .helpers import fixtures

DB_URI = os.getenv('DB_URI', 'postgresql://asterisk:proformatique@localhost:{port}')


def new_uuid():
    return str(uuid.uuid4())


class DBStarter(AssetLaunchingTestCase):

    asset = 'database'
    assets_root = os.path.join(os.path.dirname(__file__), '..', 'assets')
    service = 'postgres'


def setup():
    DBStarter.setUpClass()


def teardown():
    DBStarter.tearDownClass()


class TestPolicyCRUD(unittest.TestCase):

    def setUp(self):
        self._crud = database._PolicyCRUD(DB_URI.format(port=DBStarter.service_port(5432, 'postgres')))
        default_user_policy = self._crud.get(search='wazo_default_user_policy')[0]
        default_admin_policy = self._crud.get(search='wazo_default_admin_policy')[0]
        self._default_user_policy_uuid = default_user_policy['uuid']
        self._default_admin_policy_uuid = default_admin_policy['uuid']

    def test_template_association(self):
        assert_that(
            calling(self._crud.associate_policy_template).with_args('unknown', '#'),
            raises(exceptions.UnknownPolicyException))
        assert_that(
            calling(self._crud.dissociate_policy_template).with_args('unknown', '#'),
            raises(exceptions.UnknownPolicyException))

        with self._new_policy(u'testé', u'descriptioñ', []) as uuid_:
            self._crud.associate_policy_template(uuid_, '#')
            policy = self.get_policy(uuid_)
            assert_that(policy['acl_templates'], contains_inanyorder('#'))

            assert_that(
                calling(self._crud.associate_policy_template).with_args(uuid_, '#'),
                raises(exceptions.DuplicateTemplateException))

            self._crud.dissociate_policy_template(uuid_, '#')
            policy = self.get_policy(uuid_)
            assert_that(policy['acl_templates'], empty())

    def test_create(self):
        acl_templates = ['dird.#', 'confd.line.42.*']
        with self._new_policy(u'testé', u'descriptioñ', acl_templates) as uuid_:
            policy = self.get_policy(uuid_)

            assert_that(policy['uuid'], equal_to(uuid_))
            assert_that(policy['name'], equal_to(u'testé'))
            assert_that(policy['description'], equal_to(u'descriptioñ'))
            assert_that(policy['acl_templates'], contains_inanyorder(*acl_templates))

    def test_that_two_policies_cannot_have_the_same_name(self):
        duplicated_name = 'foobar'
        with self._new_policy(duplicated_name, u'descriptioñ'):
            assert_that(
                calling(self._crud.create).with_args(duplicated_name, '', []),
                raises(exceptions.DuplicatePolicyException))

    def test_get(self):
        with self._new_policy('foobar', '') as uuid_:
            policy = self.get_policy(uuid_)
            assert_that(policy['uuid'], equal_to(uuid_))
            assert_that(policy['name'], equal_to('foobar'))
            assert_that(policy['description'], equal_to(''))
            assert_that(policy['acl_templates'], empty())

        unknown_uuid = new_uuid()
        result = self._crud.get(search=unknown_uuid)
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
                contains(a, b, c, self._default_admin_policy_uuid, self._default_user_policy_uuid))

            result = self.list_policy(order='name', direction='desc')
            assert_that(
                result,
                contains(self._default_user_policy_uuid, self._default_admin_policy_uuid, c, b, a))

            result = self.list_policy(order='description', direction='asc')
            assert_that(
                result,
                contains(self._default_admin_policy_uuid, self._default_user_policy_uuid, c, b, a))

            result = self.list_policy(order='description', direction='desc')
            assert_that(
                result,
                contains(a, b, c, self._default_user_policy_uuid, self._default_admin_policy_uuid))

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
                contains(b, c, self._default_admin_policy_uuid, self._default_user_policy_uuid))

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

    def test_delete(self):
        uuid_ = self._crud.create('foobar', '', [])
        self._crud.delete(uuid_)
        assert_that(
            calling(self._crud.delete).with_args(uuid_),
            raises(exceptions.UnknownPolicyException))

    def test_update(self):
        assert_that(
            calling(self._crud.update).with_args('unknown', 'foo', '', []),
            raises(exceptions.UnknownPolicyException))

        with self._new_policy('foobar',
                              'This is the description',
                              ['confd.line.{{ line_id }}', 'dird.#']) as uuid_:
            self._crud.update(
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
        for policy in self._crud.get(search=policy_uuid, order='name', direction='asc'):
            return policy

    def list_policy(self, order=None, direction=None, limit=None, offset=None):
        policies = self._crud.get(search='%', order=order, direction=direction, limit=limit, offset=offset)
        return [policy['uuid'] for policy in policies]

    @contextmanager
    def _new_policy(self, name, description, acl_templates=None):
        acl_templates = acl_templates or []
        uuid_ = self._crud.create(name, description, acl_templates)
        try:
            yield uuid_
        finally:
            self._crud.delete(uuid_)


class TestTokenCRUD(unittest.TestCase):

    def setUp(self):
        self._crud = database._TokenCRUD(DB_URI.format(port=DBStarter.service_port(5432, 'postgres')))

    def test_create(self):
        with nested(self._new_token(),
                    self._new_token(acls=['first', 'second'])) as (e1, e2):
            t1 = self._crud.get(e1['uuid'])
            t2 = self._crud.get(e2['uuid'])
            assert_that(t1, equal_to(e1))
            assert_that(t2, equal_to(e2))

    def test_get(self):
        self.assertRaises(database.UnknownTokenException, self._crud.get,
                          'unknown')
        with nested(self._new_token(),
                    self._new_token(),
                    self._new_token()) as (_, expected_token, __):
            token = self._crud.get(expected_token['uuid'])
        assert_that(token, equal_to(expected_token))

    def test_delete(self):
        with self._new_token() as token:
            self._crud.delete(token['uuid'])
            self.assertRaises(database.UnknownTokenException, self._crud.get,
                              token['uuid'])
            self._crud.delete(token['uuid'])  # No error on delete unknown

    def test_delete_expired_tokens(self):
        with nested(
                self._new_token(),
                self._new_token(expiration=0),
                self._new_token(expiration=0),
        ) as (a, b, c):
            expired = [b, c]
            valid = [a]

            self._crud.delete_expired_tokens()

            for token in valid:
                assert_that(calling(self._crud.get).with_args(token['uuid']),
                            not_(raises(exceptions.UnknownTokenException)))
            for token in expired:
                assert_that(calling(self._crud.get).with_args(token['uuid']),
                            raises(exceptions.UnknownTokenException))

    @contextmanager
    def _new_token(self, acls=None, expiration=120):
        now = int(time.time())
        body = {
            'auth_id': 'test',
            'xivo_user_uuid': new_uuid(),
            'xivo_uuid': new_uuid(),
            'issued_t': now,
            'expire_t': now + expiration,
            'acls': acls or [],
        }
        token_uuid = self._crud.create(body)
        token_data = dict(body)
        token_data['uuid'] = token_uuid
        yield token_data
        self._crud.delete(token_uuid)


class TestUserCrud(unittest.TestCase):

    salt = os.urandom(64)

    def setUp(self):
        self._crud = database._UserCRUD(DB_URI.format(port=DBStarter.service_port(5432, 'postgres')))
        with self._crud.new_session() as s:
            s.query(database.User).delete()
            s.query(database.Email).delete()

    def test_user_creation(self):
        username = 'foobar'
        hash_ = 'the_hashed_password'
        email_address = 'foobar@example.com'

        user_uuid = self._crud.create(username, email_address, hash_, self.salt)

        assert_that(user_uuid, equal_to(ANY_UUID))
        with self._crud.new_session() as s:
            user = s.query(database.User).filter(database.User.uuid == user_uuid).first()
            assert_that(
                user,
                has_properties(
                    'username', username,
                    'password_hash', hash_,
                    'password_salt', self.salt,
                )
            )

            email = s.query(
                database.Email
            ).join(
                database.UserEmail, database.Email.uuid == database.UserEmail.email_uuid,
            ).join(
                database.User, database.User.uuid == database.UserEmail.user_uuid,
            ).filter(
                database.User.uuid == user.uuid,
                database.UserEmail.main == True,
            ).first()
            assert_that(
                email,
                has_properties(
                    'address', email_address,
                    'confirmed', False,
                )
            )

    def test_that_the_username_is_unique(self):
        username = 'foobar'

        self._crud.create(username, 'foobar@example.com', 'hash_one', self.salt)
        assert_that(
            calling(self._crud.create).with_args(username, 'foobar@wazo.community', 'hash_two', self.salt),
            raises(
                exceptions.ConflictException,
                has_properties(
                    'status_code', 409,
                    'resource', 'users',
                    'details', has_entries('username', ANY),
                ),
            ),
        )

    def test_that_the_email_is_unique(self):
        email = 'foobar@example.com'

        self._crud.create('foo', email, 'hash_one', self.salt)
        assert_that(
            calling(self._crud.create).with_args('bar', email, 'hash_two', self.salt),
            raises(
                exceptions.ConflictException,
                has_properties(
                    'status_code', 409,
                    'resource', 'users',
                    'details', has_entries('email_address', ANY),
                ),
            ),
        )

    @fixtures.user()
    @fixtures.user()
    @fixtures.user()
    def test_user_count_no_search_term_no_strict_filter(self, a, b, c):
        result = self._crud.count()
        assert_that(result, equal_to(3))

    @fixtures.user(username='foo')
    @fixtures.user(email_address='foobar@example.com')
    @fixtures.user()
    def test_user_count_no_search_term_strict_filter(self, a, b, c):
        result = self._crud.count(username='foo')
        assert_that(result, equal_to(1))

        result = self._crud.count(email_address='foobar@example.com')
        assert_that(result, equal_to(1))

        result = self._crud.count(uuid=c)
        assert_that(result, equal_to(1))

    @fixtures.user(username='foo')
    @fixtures.user(email_address='foobar@example.com')
    @fixtures.user()
    def test_user_count_search_term(self, a, b, c):
        result = self._crud.count(search='%foo%')
        assert_that(result, equal_to(2))

    @fixtures.user(username='foo')
    @fixtures.user(email_address='foobar@example.com')
    @fixtures.user()
    def test_user_count_mixed_strict_and_search(self, a, b, c):
        result = self._crud.count(search='%foo%', uuid=a)
        assert_that(result, equal_to(0))

    @fixtures.user(username='foo')
    @fixtures.user(email_address='foobar@example.com')
    @fixtures.user()
    def test_user_count_unfiltered(self, a, b, c):
        result = self._crud.count(search='%foo%', filtered=False)
        assert_that(result, equal_to(3))

        result = self._crud.count(uuid=a, filtered=False)
        assert_that(result, equal_to(3))

    @fixtures.user(username='a', email_address='a@example.com')
    @fixtures.user(username='b', email_address='b@example.com')
    @fixtures.user(username='c', email_address='c@example.com')
    def test_user_list_no_search_term_no_strict_filter(self, c, b, a):
        result = self._crud.list_()

        assert_that(
            result,
            contains_inanyorder(
                has_entries(
                    'uuid', a,
                    'username', 'a',
                    'emails', contains_inanyorder(
                        has_entries(
                            'address', 'a@example.com',
                            'main', True,
                            'confirmed', False,
                        ),
                    ),
                ),
                has_entries(
                    'uuid', b,
                    'username', 'b',
                    'emails', contains_inanyorder(
                        has_entries(
                            'address', 'b@example.com',
                            'main', True,
                            'confirmed', False,
                        ),
                    ),
                ),
                has_entries(
                    'uuid', c,
                    'username', 'c',
                    'emails', contains_inanyorder(
                        has_entries(
                            'address', 'c@example.com',
                            'main', True,
                            'confirmed', False,
                        ),
                    ),
                )
            )
        )

    @fixtures.user(username='foo', email_address='foo@example.com')
    @fixtures.user(username='bar', email_address='bar@example.com')
    @fixtures.user(username='baz', email_address='baz@example.com')
    def test_user_list_with_search_term(self, baz, bar, foo):
        result = self._crud.list_(search='%@example.%')

        assert_that(
            result,
            contains_inanyorder(
                has_entries(
                    'uuid', foo,
                    'username', 'foo',
                    'emails', contains_inanyorder(
                        has_entries(
                            'address', 'foo@example.com',
                            'main', True,
                            'confirmed', False,
                        ),
                    ),
                ),
                has_entries(
                    'uuid', bar,
                    'username', 'bar',
                    'emails', contains_inanyorder(
                        has_entries(
                            'address', 'bar@example.com',
                            'main', True,
                            'confirmed', False,
                        ),
                    ),
                ),
                has_entries(
                    'uuid', baz,
                    'username', 'baz',
                    'emails', contains_inanyorder(
                        has_entries(
                            'address', 'baz@example.com',
                            'main', True,
                            'confirmed', False,
                        ),
                    ),
                )
            )
        )

        result = self._crud.list_(search='foo')
        assert_that(
            result,
            contains_inanyorder(
                has_entries(
                    'uuid', foo,
                    'username', 'foo',
                    'emails', contains_inanyorder(
                        has_entries(
                            'address', 'foo@example.com',
                            'main', True,
                            'confirmed', False,
                        ),
                    ),
                )
            )
        )

    @fixtures.user(username='foo', email_address='foo@example.com')
    @fixtures.user(username='bar', email_address='bar@example.com')
    @fixtures.user(username='baz', email_address='baz@example.com')
    def test_user_list_with_strict_filters(self, baz, bar, foo):
        result = self._crud.list_(username='foo')

        assert_that(
            result,
            contains_inanyorder(
                has_entries(
                    'uuid', foo,
                    'username', 'foo',
                    'emails', contains_inanyorder(
                        has_entries(
                            'address', 'foo@example.com',
                            'main', True,
                            'confirmed', False,
                        ),
                    ),
                ),
            )
        )

        result = self._crud.list_(uuid=foo)
        assert_that(
            result,
            contains_inanyorder(
                has_entries(
                    'uuid', foo,
                    'username', 'foo',
                    'emails', contains_inanyorder(
                        has_entries(
                            'address', 'foo@example.com',
                            'main', True,
                            'confirmed', False,
                        ),
                    ),
                )
            )
        )

    @fixtures.user(username='foo', email_address='foo@example.com')
    @fixtures.user(username='bar', email_address='bar@example.com')
    @fixtures.user(username='baz', email_address='baz@example.com')
    def test_user_list_with_strict_filters_and_search(self, baz, bar, foo):
        result = self._crud.list_(username='foo', search='%baz%')
        assert_that(result, empty())

        result = self._crud.list_(uuid=foo, search='%example%')
        assert_that(
            result,
            contains_inanyorder(
                has_entries(
                    'uuid', foo,
                    'username', 'foo',
                    'emails', contains_inanyorder(
                        has_entries(
                            'address', 'foo@example.com',
                            'main', True,
                            'confirmed', False,
                        ),
                    ),
                )
            )
        )

    @fixtures.user(username='a')
    @fixtures.user(username='b')
    @fixtures.user(username='c')
    @fixtures.user(username='d')
    @fixtures.user(username='e')
    @fixtures.user(username='f')
    @fixtures.user(username='g')
    @fixtures.user(username='h')
    @fixtures.user(username='i')
    def test_pagination(self, i, h, g, f, e, d, c, b, a):
        result = self._crud.list_(order='username', direction='desc', limit=1, offset=0)
        assert_that(result, contains_inanyorder(
            has_entries('uuid', i),
        ))

        result = self._crud.list_(order='username', direction='asc', limit=2, offset=1)
        assert_that(result, contains_inanyorder(
            has_entries('uuid', b),
            has_entries('uuid', c),
        ))

        result = self._crud.list_(order='username', direction='asc', limit=2, offset=1)
        assert_that(result, contains_inanyorder(
            has_entries('uuid', b),
            has_entries('uuid', c),
        ))

    @fixtures.user()
    def test_delete(self, user_uuid):
        self._crud.delete(user_uuid)

        assert_that(
            calling(self._crud.delete).with_args(user_uuid),
            raises(exceptions.UnknownUserException),
        )

    @fixtures.user(username='foobar')
    def test_get_credential(self, user_uuid):
        assert_that(
            calling(self._crud.get_credentials).with_args('not-foobar'),
            raises(exceptions.UnknownUsernameException),
        )

        hash_, salt = self._crud.get_credentials('foobar')
        assert_that(hash_, not_(none()))
        assert_that(salt, not_(none()))
