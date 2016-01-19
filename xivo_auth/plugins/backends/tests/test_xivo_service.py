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
from hamcrest import assert_that, equal_to, empty

from xivo_auth.plugins import backends


class TestVerifyPassword(unittest.TestCase):

    @patch('xivo_auth.plugins.backends.xivo_service.accesswebservice_dao.check_username_password')
    def test_that_get_uuid_calls_the_dao(self, dao_mock):
        dao_mock.return_value = 'a_return_value'
        backend = backends.XiVOService('config')

        result = backend.verify_password('foo', 'bar')

        assert_that(result, equal_to('a_return_value'))
        dao_mock.assert_called_once_with('foo', 'bar')

    @patch('xivo_auth.plugins.backends.xivo_service.accesswebservice_dao.get_user_acl',
           Mock(return_value=['confd.#', 'dird.#']))
    def test_that_get_acls_return_acl_for_confd(self):
        backend = backends.XiVOService({})

        acls = backend.get_acls('foo', None)

        assert_that(acls, equal_to(['confd.#', 'dird.#']))

    @patch('xivo_auth.plugins.backends.xivo_service.accesswebservice_dao.get_user_acl',
           Mock(return_value=['confd.#', 'dird.#']))
    def test_that_get_consul_acls_return_acl_for_dird(self):
        backend = backends.XiVOService({})
        expected_result = [{'rule': 'xivo/private',
                            'policy': 'read'}]

        consul_acl = backend.get_consul_acls('foo', None)

        assert_that(consul_acl, equal_to(expected_result))

    @patch('xivo_auth.plugins.backends.xivo_service.accesswebservice_dao.get_user_acl',
           Mock(return_value=['confd.#', '#.dird']))
    def test_that_get_consul_acls_return_empty_list(self):
        backend = backends.XiVOService({})

        consul_acl = backend.get_consul_acls('foo', None)

        assert_that(consul_acl, empty())

    @patch('xivo_auth.plugins.backends.xivo_service.accesswebservice_dao.get_user_id', Mock(return_value=42))
    def test_that_get_ids_returns_the_id_and_None(self):
        backend = backends.XiVOService({})

        auth_id, xivo_user_uuid = backend.get_ids('foo', None)

        assert_that(auth_id, equal_to('42'))
        assert_that(xivo_user_uuid, equal_to(None))
