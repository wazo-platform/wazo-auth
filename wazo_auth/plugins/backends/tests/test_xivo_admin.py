# -*- coding: utf-8 -*-
#
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
#
# SPDX-License-Identifier: GPL-3.0+

import unittest

from mock import Mock, patch, sentinel as s
from hamcrest import assert_that, calling, equal_to, has_entry, raises

from wazo_auth.plugins import backends
from wazo_auth.exceptions import ManagerException
from wazo_auth.plugins.backends.xivo_admin import NotFoundError


class TestGetAdminData(unittest.TestCase):

    def setUp(self):
        self.backend = backends.XiVOAdmin()

    @patch('wazo_auth.plugins.backends.xivo_admin.admin_dao')
    def test_that_returned_contains_the_entity(self, admin_dao_mock):
        tenant = admin_dao_mock.get_admin_entity.return_value = 'the-entity'

        result = self.backend.get_admin_data(s.login)

        admin_dao_mock.get_admin_entity.assert_called_once_with(s.login)
        assert_that(result, has_entry('entity', tenant))


class TestVerifyPassword(unittest.TestCase):

    @patch('wazo_auth.plugins.backends.xivo_admin.admin_dao')
    def test_that_get_uuid_calls_the_dao(self, admin_dao_mock):
        admin_dao_mock.check_username_password.return_value = 'a_return_value'
        backend = backends.XiVOAdmin()

        result = backend.verify_password('foo', 'bar', None)

        assert_that(result, equal_to('a_return_value'))
        admin_dao_mock.check_username_password.assert_called_once_with('foo', 'bar')

    @patch('wazo_auth.plugins.backends.xivo_admin.admin_dao.get_admin_uuid',
           Mock(return_value='5900b8d4-5c38-49f9-b5fc-e0b7057b4c50'))
    def test_that_get_ids_returns_the_uuid_and_None(self):
        backend = backends.XiVOAdmin()

        auth_id, xivo_user_uuid = backend.get_ids('foo', None)

        assert_that(auth_id, equal_to('5900b8d4-5c38-49f9-b5fc-e0b7057b4c50'))
        assert_that(xivo_user_uuid, equal_to(None))

    @patch('wazo_auth.plugins.backends.xivo_admin.admin_dao.get_admin_uuid',
           Mock(side_effect=NotFoundError))
    def test_that_a_manager_error_is_raised_if_username_not_found(self):
        backend = backends.XiVOAdmin()

        assert_that(
            calling(backend.get_ids).with_args('foo', None),
            raises(ManagerException))
