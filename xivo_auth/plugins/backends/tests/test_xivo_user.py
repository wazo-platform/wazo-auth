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

from xivo_dao.alchemy.userfeatures import UserFeatures as User
from xivo_dao.helpers.exception import InputError

from mock import patch, Mock
from hamcrest import assert_that, equal_to

from xivo_auth.plugins.backends.default_acls import DEFAULT_USER_ACLS
from xivo_auth.plugins.backends.xivo_user import XiVOUser


@patch('xivo_auth.plugins.backends.xivo_user.user_dao')
class TestGetIDS(unittest.TestCase):

    def test_that_get_ids_calls_the_dao(self, user_dao_mock):
        user_dao_mock.get_by.return_value = Mock(User, uuid='foobars-uuid')
        backend = XiVOUser('config')
        args = None

        result = backend.get_ids('foobar', args)

        assert_that(result, equal_to(('foobars-uuid', 'foobars-uuid')))
        user_dao_mock.get_by.assert_called_once_with(username='foobar', enableclient=1)

    def test_that_get_ids_raises_if_no_user(self, user_dao_mock):
        user_dao_mock.get_by.side_effect = InputError
        backend = XiVOUser('config')

        self.assertRaises(Exception, backend.get_ids, 'foobar')


@patch('xivo_auth.plugins.backends.xivo_user.user_dao')
class TestVerifyPassword(unittest.TestCase):

    def test_that_verify_password_calls_the_dao(self, user_dao_mock):
        user_dao_mock.find_by.return_value = Mock(User)
        backend = XiVOUser('config')

        result = backend.verify_password('foo', 'bar', None)

        assert_that(result, equal_to(True))
        user_dao_mock.find_by.assert_called_once_with(username='foo',
                                                      password='bar',
                                                      enableclient=1)


class TestGetAcls(unittest.TestCase):

    def test_that_get_acls_returns_the_right_acls(self):
        backend = XiVOUser('config')

        result = backend.get_acls('foo', 'bar')

        assert_that(result, equal_to(DEFAULT_USER_ACLS))
