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

from xivo_dao.alchemy.userfeatures import UserFeatures as User
from xivo_dao.helpers.exception import InputError

from mock import patch, Mock
from hamcrest import assert_that, equal_to, is_

from wazo_auth.plugins.backends.xivo_user import XiVOUser

DEFAULT_USER_ACLS = [
    'call-logd.users.me.cdr.read',
    'confd.infos.read',
    'confd.users.me.read',
    'confd.users.me.update',
    'confd.users.me.funckeys.*',
    'confd.users.me.funckeys.*.*',
    'confd.users.me.#.read',
    'confd.users.me.services.*.*',
    'confd.users.me.forwards.*.*',
    'ctid-ng.users.me.#',
    'ctid-ng.users.*.presences.read',
    'ctid-ng.lines.*.presences.read',
    'ctid-ng.switchboards.#',
    'ctid-ng.transfers.*.read',
    'ctid-ng.transfers.*.delete',
    'ctid-ng.transfers.*.complete.update',
    'dird.#.me.read',
    'dird.directories.favorites.#',
    'dird.directories.lookup.*.headers.read',
    'dird.directories.lookup.*.read',
    'dird.directories.personal.*.read',
    'dird.personal.#',
    'events.calls.me',
    'events.chat.message.*.me',
    'events.config.users.me.#',
    'events.statuses.*',
    'events.switchboards.#',
    'events.transfers.me',
    'events.users.me.#',
    'events.directory.me.#',
    'websocketd'
]


@patch('wazo_auth.plugins.backends.xivo_user.user_dao')
class TestGetIDS(unittest.TestCase):

    def test_that_get_ids_calls_the_dao(self, user_dao_mock):
        user_dao_mock.get_by.return_value = Mock(User, uuid='foobars-uuid')
        backend = XiVOUser({'confd': {'host': 'localhost'}})
        args = None

        result = backend.get_ids('foobar', args)

        assert_that(result, equal_to(('foobars-uuid', 'foobars-uuid')))
        user_dao_mock.get_by.assert_called_once_with(username='foobar', enableclient=1)

    def test_that_get_ids_raises_if_no_user(self, user_dao_mock):
        user_dao_mock.get_by.side_effect = InputError
        backend = XiVOUser({'confd': {'host': 'localhost'}})

        self.assertRaises(Exception, backend.get_ids, 'foobar')


@patch('wazo_auth.plugins.backends.xivo_user.user_dao')
class TestVerifyPassword(unittest.TestCase):

    def test_that_verify_password_calls_the_dao(self, user_dao_mock):
        user_dao_mock.find_by.return_value = Mock(User)
        backend = XiVOUser({'confd': {'host': 'localhost'}})

        result = backend.verify_password('foo', 'bar', None)

        assert_that(result, equal_to(True))
        user_dao_mock.find_by.assert_called_once_with(username='foo',
                                                      password='bar',
                                                      enableclient=1)


@patch('wazo_auth.interfaces.Client')
class TestGetAcls(unittest.TestCase):

    def setUp(self):
        self.backend = XiVOUser({'confd': {'host': 'localhost'}})

    def test_that_get_acls_returns_the_right_acls(self, _ConfdClient):
        result = self.backend.get_acls('foo', {'acl_templates': DEFAULT_USER_ACLS})

        assert_that(result, equal_to(DEFAULT_USER_ACLS))

    def test_that_confd_is_not_called_if_no_acl_templates(self, _ConfdClient):
        args = [{'acl_templates': []}, {}]

        with patch.object(self.backend, 'get_user_data') as get_user_data:
            for arg in args:
                self.backend.get_acls('foo', arg)
                assert_that(get_user_data.called, is_(False), arg)
                get_user_data.reset_mock()
