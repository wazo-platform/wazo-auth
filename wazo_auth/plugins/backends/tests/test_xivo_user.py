# -*- coding: utf-8 -*-
# Copyright 2015-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import unittest

from xivo_dao.alchemy.userfeatures import UserFeatures as User
from xivo_dao.helpers.exception import InputError

from mock import patch, Mock
from hamcrest import assert_that, equal_to, has_entries, is_

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
class TestGetMetadata(unittest.TestCase):

    def test_that_get_metadata_calls_the_dao(self, user_dao_mock):
        user_dao_mock.get_by.return_value = Mock(User, uuid='foobars-uuid')
        backend = XiVOUser()
        backend.load({'config': {'confd': {'host': 'localhost'}}})
        args = None

        result = backend.get_metadata('foobar', args)

        assert_that(result, has_entries(auth_id='foobars-uuid', xivo_user_uuid='foobars-uuid'))
        user_dao_mock.get_by.assert_called_once_with(username='foobar', enableclient=1)

    def test_that_get_metadata_raises_if_no_user(self, user_dao_mock):
        user_dao_mock.get_by.side_effect = InputError
        backend = XiVOUser()
        backend.load({'config': {'confd': {'host': 'localhost'}}})

        self.assertRaises(Exception, backend.get_metadata, 'foobar', None)


@patch('wazo_auth.plugins.backends.xivo_user.user_dao')
class TestVerifyPassword(unittest.TestCase):

    def test_that_verify_password_calls_the_dao(self, user_dao_mock):
        user_dao_mock.find_by.return_value = Mock(User)
        backend = XiVOUser()
        backend.load({'config': {'confd': {'host': 'localhost'}}})

        result = backend.verify_password('foo', 'bar', None)

        assert_that(result, equal_to(True))
        user_dao_mock.find_by.assert_called_once_with(username='foo',
                                                      password='bar',
                                                      enableclient=1)


@patch('wazo_auth.interfaces.Client')
class TestGetAcls(unittest.TestCase):

    def setUp(self):
        self.backend = XiVOUser()
        self.backend.load({'config': {'confd': {'host': 'localhost'}}})

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
