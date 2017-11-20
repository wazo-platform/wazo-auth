# -*- coding: utf-8 -*-
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import unittest

from mock import Mock, patch
from hamcrest import assert_that, calling, equal_to, raises

from wazo_auth.plugins import backends
from wazo_auth.exceptions import AuthenticationFailedException


class TestVerifyPassword(unittest.TestCase):

    @patch('wazo_auth.plugins.backends.xivo_service.accesswebservice_dao.check_username_password')
    def test_that_get_uuid_calls_the_dao(self, dao_mock):
        dao_mock.return_value = 'a_return_value'
        backend = backends.XiVOService()

        result = backend.verify_password('foo', 'bar', None)

        assert_that(result, equal_to('a_return_value'))
        dao_mock.assert_called_once_with('foo', 'bar')

    @patch('wazo_auth.plugins.backends.xivo_service.accesswebservice_dao.get_user_acl',
           Mock(return_value=['confd.#', 'dird.#']))
    def test_that_get_acls_return_acl_for_confd(self):
        backend = backends.XiVOService()

        acls = backend.get_acls('foo', None)

        assert_that(acls, equal_to(['confd.#', 'dird.#']))

    @patch('wazo_auth.plugins.backends.xivo_service.accesswebservice_dao.get_user_uuid',
           Mock(return_value='534ede0d-9395-445a-8541-96b99e7b16a5'))
    def test_that_get_ids_returns_the_id_and_None(self):
        backend = backends.XiVOService()

        auth_id, xivo_user_uuid = backend.get_ids('foo', None)

        assert_that(auth_id, equal_to('534ede0d-9395-445a-8541-96b99e7b16a5'))
        assert_that(xivo_user_uuid, equal_to(None))

    @patch('wazo_auth.plugins.backends.xivo_service.accesswebservice_dao.get_user_uuid',
           Mock(side_effect=LookupError))
    def test_that_a_manager_error_is_raised_if_not_found(self):
        backend = backends.XiVOService()

        assert_that(
            calling(backend.get_ids).with_args('foo', None),
            raises(AuthenticationFailedException))
