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
from hamcrest import assert_that, calling, contains_inanyorder, equal_to, empty, raises
from xivo_test_helpers.asset_launching_test_case import AssetLaunchingTestCase

from xivo_auth import database, exceptions

DB_URI = os.getenv('DB_URI', 'postgresql://asterisk:proformatique@localhost:15432')


def new_uuid():
    return str(uuid.uuid4())


class DBStarter(AssetLaunchingTestCase):

    asset = 'database'
    assets_root = os.path.join(os.path.dirname(__file__), '..', 'assets')


def setup():
    DBStarter.setUpClass()


def teardown():
    DBStarter.tearDownClass()


class TestPolicyCRUD(unittest.TestCase):

    def setUp(self):
        self._crud = database._PolicyCRUD(database._ConnectionFactory(DB_URI))

    def test_create(self):
        acl_templates = ['dird.#', 'confd.line.42.*']
        with self._new_policy('testé', 'descriptioñ', acl_templates) as uuid_:
            policy = self.get_policy(uuid_)

            assert_that(policy['uuid'], equal_to(uuid_))
            assert_that(policy['name'], equal_to('testé'))
            assert_that(policy['description'], equal_to('descriptioñ'))
            assert_that(policy['acl_templates'], contains_inanyorder(*acl_templates))

    def test_that_two_policies_cannot_have_the_same_name(self):
        duplicated_name = 'foobar'
        with self._new_policy(duplicated_name, 'descriptioñ'):
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
        assert_that(
            calling(self._crud.get).with_args(unknown_uuid),
            raises(exceptions.UnknownPolicyException))

    def test_delete(self):
        uuid_ = self._crud.create('foobar', '', [])
        self._crud.delete(uuid_)
        assert_that(
            calling(self._crud.delete).with_args(uuid_),
            raises(exceptions.UnknownPolicyException))

    def get_policy(self, policy_uuid):
        for policy in self._crud.get(policy_uuid):
            return policy

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
        self._crud = database._TokenCRUD(database._ConnectionFactory(DB_URI))

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

    @contextmanager
    def _new_token(self, acls=None):
        now = int(time.time())
        body = {
            'auth_id': 'test',
            'xivo_user_uuid': new_uuid(),
            'xivo_uuid': new_uuid(),
            'issued_t': now,
            'expire_t': now + 120,
            'acls': acls or [],
        }
        token_uuid = self._crud.create(body)
        token_data = dict(body)
        token_data['uuid'] = token_uuid
        yield token_data
        self._crud.delete(token_uuid)
