# -*- coding: utf-8 -*-
#
# Copyright 2016 The Wazo Authors  (see the AUTHORS file)
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
from hamcrest import assert_that, equal_to
from xivo_test_helpers.asset_launching_test_case import AssetLaunchingTestCase

from xivo_auth import database

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


class TestTokenCRUD(unittest.TestCase):

    def setUp(self):
        self._crud = database._TokenCRUD(DB_URI)

    def test_get(self):
        self.assertRaises(database.UnknownTokenException, self._crud.get,
                          'unknown')
        with nested(self._new_token(),
                    self._new_token(),
                    self._new_token()) as (_, expected_token, __):
            expected_token.pop('acls')  # TODO handle ACL
            token = self._crud.get(expected_token['uuid'])
        assert_that(token, equal_to(expected_token))

    def test_delete(self):
        with self._new_token() as token:
            self._crud.delete(token['uuid'])
            self.assertRaises(database.UnknownTokenException, self._crud.get,
                              token['uuid'])
            self._crud.delete(token['uuid'])  # No error on delete unknown

    @contextmanager
    def _new_token(self):
        now = int(time.time())
        body = {
            'auth_id': 'test',
            'xivo_user_uuid': new_uuid(),
            'xivo_uuid': new_uuid(),
            'issued_t': now,
            'expire_t': now + 120,
            'acls': [],
        }
        token_uuid = self._crud.create(body)
        token_data = dict(body)
        token_data['uuid'] = token_uuid
        yield token_data
        self._crud.delete(token_uuid)
