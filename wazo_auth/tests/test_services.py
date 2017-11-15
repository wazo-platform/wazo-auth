# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import assert_that, equal_to
from mock import Mock, sentinel as s
from unittest import TestCase

from .. import services, database


class TestUserService(TestCase):

    def setUp(self):
        self.encrypter = Mock(services.PasswordEncrypter)
        self.user_crud = Mock(database._UserCRUD)
        dao = database.DAO(Mock(), Mock(), self.user_crud, Mock(), Mock())
        self.service = services.UserService(dao, encrypter=self.encrypter)

    def test_that_new(self):
        params = dict(
            username='foobar',
            password='s3cre7',
            email_address='foobar@example.com',
        )
        expected_db_params = dict(
            username='foobar',
            email_address='foobar@example.com',
            salt=s.salt,
            hash_=s.hash_,
        )
        self.encrypter.encrypt_password.return_value = s.salt, s.hash_

        result = self.service.new_user(**params)

        self.user_crud.create.assert_called_once_with(**expected_db_params)
        assert_that(result, equal_to(self.user_crud.create.return_value))
