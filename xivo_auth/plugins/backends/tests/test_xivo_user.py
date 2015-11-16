# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Avencall
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

from xivo_auth.plugins import backends


@patch('xivo_auth.plugins.backends.xivo_user.user_dao')
class TestGetIDS(unittest.TestCase):

    def test_that_get_ids_calls_the_dao(self, user_dao_mock):
        user_dao_mock.get_by.return_value = Mock(User, uuid='foobars-uuid')
        backend = backends.XiVOUser('config')
        args = None

        result = backend.get_ids('foobar', args)

        assert_that(result, equal_to(('foobars-uuid', 'foobars-uuid')))
        user_dao_mock.get_by.assert_called_once_with(username='foobar', enableclient=1)

    def test_that_get_ids_raises_if_no_user(self, user_dao_mock):
        user_dao_mock.get_by.side_effect = InputError
        backend = backends.XiVOUser('config')

        self.assertRaises(Exception, backend.get_ids, 'foobar')


@patch('xivo_auth.plugins.backends.xivo_user.user_dao')
class TestGetACLS(unittest.TestCase):

    def test_that_get_consul_acls_calls_get_ids(self, user_dao_mock):
        user_dao_mock.get_by.return_value = Mock(User, uuid='foobars-uuid')
        backend = backends.XiVOUser('config')
        args = None

        result = backend.get_consul_acls('foobar', args)

        acls = [{'rule': 'xivo/private/foobars-uuid', 'policy': 'write'}]
        assert_that(result, equal_to((acls)))
        user_dao_mock.get_by.assert_called_once_with(username='foobar', enableclient=1)


@patch('xivo_auth.plugins.backends.xivo_user.user_dao')
class TestVerifyPassword(unittest.TestCase):

    def test_that_verify_password_calls_the_dao(self, user_dao_mock):
        user_dao_mock.find_by.return_value = Mock(User)
        backend = backends.XiVOUser('config')

        result = backend.verify_password('foo', 'bar')

        assert_that(result, equal_to(True))
        user_dao_mock.find_by.assert_called_once_with(username='foo',
                                                      password='bar',
                                                      enableclient=1)
