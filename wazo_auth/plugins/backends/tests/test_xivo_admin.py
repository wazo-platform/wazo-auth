# Copyright 2015-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import unittest

from mock import Mock, patch, sentinel as s
from hamcrest import assert_that, calling, equal_to, has_entries, raises

from wazo_auth.exceptions import ManagerException
from wazo_auth.plugins.backends.xivo_admin import NotFoundError, XiVOAdmin


class TestGetMetadata(unittest.TestCase):

    def setUp(self):
        self.backend = XiVOAdmin()
        self.tenant_service = self.backend._tenant_service = Mock()

    @patch('wazo_auth.plugins.backends.xivo_admin.admin_dao.get_admin_uuid',
           Mock(return_value='5900b8d4-5c38-49f9-b5fc-e0b7057b4c50'))
    @patch('wazo_auth.plugins.backends.xivo_admin.admin_dao')
    def test_that_returned_contains_the_entity(self, admin_dao_mock):
        tenant, tenant_uuid = admin_dao_mock.get_admin_entity.return_value = 'the-entity', s.uuid
        self.tenant_service.list_.return_value = [{'uuid': s.uuid, 'name': tenant, 'ignored': 'field'}]

        result = self.backend.get_metadata(s.login)

        admin_dao_mock.get_admin_entity.assert_called_once_with(s.login)
        assert_that(result, has_entries(
            entity=tenant,
            auth_id='5900b8d4-5c38-49f9-b5fc-e0b7057b4c50',
            xivo_user_uuid=None,
        ))

    @patch('wazo_auth.plugins.backends.xivo_admin.admin_dao.get_admin_uuid',
           Mock(side_effect=NotFoundError))
    def test_that_a_manager_error_is_raised_if_username_not_found(self):
        backend = XiVOAdmin()

        assert_that(
            calling(backend.get_metadata).with_args('foo', None),
            raises(ManagerException),
        )


class TestVerifyPassword(unittest.TestCase):

    @patch('wazo_auth.plugins.backends.xivo_admin.admin_dao')
    def test_that_get_uuid_calls_the_dao(self, admin_dao_mock):
        admin_dao_mock.check_username_password.return_value = 'a_return_value'
        backend = XiVOAdmin()

        result = backend.verify_password('foo', 'bar', None)

        assert_that(result, equal_to('a_return_value'))
        admin_dao_mock.check_username_password.assert_called_once_with('foo', 'bar')
