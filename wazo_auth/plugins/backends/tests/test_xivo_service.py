# Copyright 2015-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import unittest

from mock import Mock, patch, sentinel as s
from hamcrest import assert_that, calling, contains_inanyorder, equal_to, has_entries, raises

from wazo_auth.exceptions import AuthenticationFailedException
from wazo_auth.plugins.backends.xivo_service import XiVOService


class TestVerifyPassword(unittest.TestCase):

    @patch('wazo_auth.plugins.backends.xivo_service.accesswebservice_dao.check_username_password')
    def test_that_get_uuid_calls_the_dao(self, dao_mock):
        dao_mock.return_value = 'a_return_value'
        backend = XiVOService()

        result = backend.verify_password('foo', 'bar', None)

        assert_that(result, equal_to('a_return_value'))
        dao_mock.assert_called_once_with('foo', 'bar')


class TestGetAcls(unittest.TestCase):

    @patch('wazo_auth.plugins.backends.xivo_service.accesswebservice_dao.get_user_acl',
           Mock(return_value=['confd.#', 'dird.#']))
    def test_that_get_acls_return_acl_for_confd(self):
        backend = XiVOService()

        acls = backend.get_acls('foo', None)

        assert_that(acls, equal_to(['confd.#', 'dird.#']))


class TestGetMetadata(unittest.TestCase):

    def setUp(self):
        self.tenant_service = Mock()
        self.tenant_service.find_top_tenant.return_value = s.top_tenant_uuid
        self.backend = XiVOService()
        self.backend._tenant_service = self.tenant_service

    @patch('wazo_auth.plugins.backends.xivo_service.accesswebservice_dao.get_user_uuid',
           Mock(return_value='534ede0d-9395-445a-8541-96b99e7b16a5'))
    def test_that_get_metadata_returns_the_id_and_None(self):
        result = self.backend.get_metadata('foo', None)

        assert_that(result, has_entries(
            auth_id='534ede0d-9395-445a-8541-96b99e7b16a5',
            xivo_user_uuid=None,
        ))

    @patch('wazo_auth.plugins.backends.xivo_service.accesswebservice_dao.get_user_uuid',
           Mock(side_effect=LookupError))
    def test_that_a_manager_error_is_raised_if_not_found(self):
        assert_that(
            calling(self.backend.get_metadata).with_args('foo', None),
            raises(AuthenticationFailedException),
        )

    @patch('wazo_auth.plugins.backends.xivo_service.accesswebservice_dao.get_user_uuid',
           Mock(return_value='534ede0d-9395-445a-8541-96b99e7b16a5'))
    def test_that_metadata_contains_all_tenants(self):
        result = self.backend.get_metadata('foo', None)

        assert_that(result, has_entries(tenant_uuid=s.top_tenant_uuid))
