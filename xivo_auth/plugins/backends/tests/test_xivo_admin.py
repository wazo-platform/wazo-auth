# -*- coding: utf-8 -*-
#
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import unittest

from mock import Mock, patch, sentinel as s
from hamcrest import assert_that, equal_to, has_item

from xivo_auth.plugins import backends


class TestGetACLS(unittest.TestCase):

    def setUp(self):
        self.backend = backends.XiVOAdmin('config')

    @patch('xivo_auth.plugins.backends.xivo_admin.admin_dao')
    def test_that_returned_acls_contains_the_entity(self, admin_dao_mock):
        tenant = admin_dao_mock.get_admin_entity.return_value = 'the-entity'

        result = self.backend.get_acls(s.login, None)

        admin_dao_mock.get_admin_entity.assert_called_once_with(s.login)
        assert_that(result, has_item('dird.tenants.{}.#'.format(tenant)))

    @patch('xivo_auth.plugins.backends.xivo_admin.admin_dao')
    def test_that_returned_acls_contains_all_entity_acl_if_not_assigned(self, admin_dao_mock):
        admin_dao_mock.get_admin_entity.return_value = None

        result = self.backend.get_acls(s.login, None)

        admin_dao_mock.get_admin_entity.assert_called_once_with(s.login)
        assert_that(result, has_item('dird.tenants.#'))

    @patch('xivo_auth.plugins.backends.xivo_admin.admin_dao', Mock())
    def test_that_get_acls_return_acl_for_confd(self):
        acls = self.backend.get_acls('foo', None)

        assert_that(acls, has_item('confd.#'))


class TestVerifyPassword(unittest.TestCase):

    @patch('xivo_auth.plugins.backends.xivo_admin.admin_dao')
    def test_that_get_uuid_calls_the_dao(self, admin_dao_mock):
        admin_dao_mock.check_username_password.return_value = 'a_return_value'
        backend = backends.XiVOAdmin('config')

        result = backend.verify_password('foo', 'bar', None)

        assert_that(result, equal_to('a_return_value'))
        admin_dao_mock.check_username_password.assert_called_once_with('foo', 'bar')

    @patch('xivo_auth.plugins.backends.xivo_admin.admin_dao.get_admin_uuid',
           Mock(return_value='5900b8d4-5c38-49f9-b5fc-e0b7057b4c50'))
    def test_that_get_ids_returns_the_uuid_and_None(self):
        backend = backends.XiVOAdmin({})

        auth_id, xivo_user_uuid = backend.get_ids('foo', None)

        assert_that(auth_id, equal_to('5900b8d4-5c38-49f9-b5fc-e0b7057b4c50'))
        assert_that(xivo_user_uuid, equal_to(None))
