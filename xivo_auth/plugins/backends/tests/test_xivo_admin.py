# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Avencall
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

from mock import Mock, patch
from hamcrest import assert_that, contains_inanyorder, equal_to, empty

from xivo_auth.plugins import backends


class TestVerifyPassword(unittest.TestCase):

    @patch('xivo_auth.plugins.backends.xivo_admin.admin_dao')
    def test_that_get_uuid_calls_the_dao(self, admin_dao_mock):
        admin_dao_mock.check_username_password.return_value = 'a_return_value'
        backend = backends.XiVOAdmin('config')

        result = backend.verify_password('foo', 'bar', None)

        assert_that(result, equal_to('a_return_value'))
        admin_dao_mock.check_username_password.assert_called_once_with('foo', 'bar')

    def test_that_get_acls_return_acl_for_confd(self):
        backend = backends.XiVOAdmin({})

        acls = backend.get_acls('foo', None)

        assert_that(acls, contains_inanyorder('confd.#'))

    def test_that_an_admin_as_no_kv_available(self):
        backend = backends.XiVOAdmin({})

        rules = backend.get_consul_acls('foo', None)

        assert_that(rules, empty())

    @patch('xivo_auth.plugins.backends.xivo_admin.admin_dao.get_admin_id', Mock(return_value=42))
    def test_that_get_ids_returns_the_id_and_None(self):
        backend = backends.XiVOAdmin({})

        auth_id, xivo_user_uuid = backend.get_ids('foo', None)

        assert_that(auth_id, equal_to('42'))
        assert_that(xivo_user_uuid, equal_to(None))
