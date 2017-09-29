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

from mock import Mock, patch
from hamcrest import assert_that, calling, equal_to, raises

from wazo_auth.plugins import backends
from wazo_auth.exceptions import AuthenticationFailedException


class TestVerifyPassword(unittest.TestCase):

    @patch('wazo_auth.plugins.backends.xivo_service.accesswebservice_dao.check_username_password')
    def test_that_get_uuid_calls_the_dao(self, dao_mock):
        dao_mock.return_value = 'a_return_value'
        backend = backends.XiVOService('config')

        result = backend.verify_password('foo', 'bar', None)

        assert_that(result, equal_to('a_return_value'))
        dao_mock.assert_called_once_with('foo', 'bar')

    @patch('wazo_auth.plugins.backends.xivo_service.accesswebservice_dao.get_user_acl',
           Mock(return_value=['confd.#', 'dird.#']))
    def test_that_get_acls_return_acl_for_confd(self):
        backend = backends.XiVOService({})

        acls = backend.get_acls('foo', None)

        assert_that(acls, equal_to(['confd.#', 'dird.#']))

    @patch('wazo_auth.plugins.backends.xivo_service.accesswebservice_dao.get_user_uuid',
           Mock(return_value='534ede0d-9395-445a-8541-96b99e7b16a5'))
    def test_that_get_ids_returns_the_id_and_None(self):
        backend = backends.XiVOService({})

        auth_id, xivo_user_uuid = backend.get_ids('foo', None)

        assert_that(auth_id, equal_to('534ede0d-9395-445a-8541-96b99e7b16a5'))
        assert_that(xivo_user_uuid, equal_to(None))

    @patch('wazo_auth.plugins.backends.xivo_service.accesswebservice_dao.get_user_uuid',
           Mock(side_effect=LookupError))
    def test_that_a_manager_error_is_raised_if_not_found(self):
        backend = backends.XiVOService({})

        assert_that(
            calling(backend.get_ids).with_args('foo', None),
            raises(AuthenticationFailedException))
