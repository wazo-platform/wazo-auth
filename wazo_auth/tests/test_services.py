# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import assert_that, calling, equal_to, not_, raises
from mock import Mock, sentinel as s
from unittest import TestCase

from .. import services, database, exceptions


class BaseServiceTestCase(TestCase):

    def setUp(self):
        self.group_dao = Mock(database._GroupDAO)
        self.policy_dao = Mock(database._PolicyDAO)
        self.tenant_dao = Mock(database._TenantDAO)
        self.token_dao = Mock(database._TokenDAO)
        self.user_dao = Mock(database._UserDAO)

        self.dao = database.DAO(
            self.policy_dao,
            self.token_dao,
            self.user_dao,
            self.tenant_dao,
            self.group_dao,
        )


class TestGroupService(BaseServiceTestCase):

    def setUp(self):
        super(TestGroupService, self).setUp()
        self.service = services.GroupService(self.dao)

    def test_remove_policy(self):
        self.group_dao.remove_policy.return_value = 0
        self.policy_dao.exists.return_value = False
        assert_that(
            calling(self.service.remove_policy).with_args(s.group_uuid, s.policy_uuid),
            raises(exceptions.UnknownPolicyException))

        self.group_dao.remove_policy.return_value = 0
        self.policy_dao.exists.return_value = True
        assert_that(
            calling(self.service.remove_policy).with_args(s.group_uuid, s.policy_uuid),
            not_(raises(Exception)))

        self.group_dao.remove_policy.return_value = 1
        self.policy_dao.exists.return_value = True
        assert_that(
            calling(self.service.remove_policy).with_args(s.group_uuid, s.policy_uuid),
            not_(raises(Exception)))

    def test_remove_user(self):
        self.group_dao.remove_user.return_value = 0
        self.user_dao.exists.return_value = False
        assert_that(
            calling(self.service.remove_user).with_args(s.group_uuid, s.user_uuid),
            raises(exceptions.UnknownUserException))

        self.group_dao.remove_user.return_value = 0
        self.user_dao.exists.return_value = True
        assert_that(
            calling(self.service.remove_user).with_args(s.group_uuid, s.user_uuid),
            not_(raises(Exception)))

        self.group_dao.remove_user.return_value = 1
        self.user_dao.exists.return_value = True
        assert_that(
            calling(self.service.remove_user).with_args(s.group_uuid, s.user_uuid),
            not_(raises(Exception)))


class TestUserService(BaseServiceTestCase):

    def setUp(self):
        super(TestUserService, self).setUp()
        self.encrypter = Mock(services.PasswordEncrypter)
        self.service = services.UserService(self.dao, encrypter=self.encrypter)

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

        self.user_dao.create.assert_called_once_with(**expected_db_params)
        assert_that(result, equal_to(self.user_dao.create.return_value))


class TestTenantService(BaseServiceTestCase):

    def setUp(self):
        super(TestTenantService, self).setUp()
        self.service = services.TenantService(self.dao)

    def test_remove_user(self):
        self.tenant_dao.remove_user.return_value = 0
        self.user_dao.exists.return_value = False
        assert_that(
            calling(self.service.remove_user).with_args(s.tenant_uuid, s.user_uuid),
            raises(exceptions.UnknownUserException))

        self.tenant_dao.remove_user.return_value = 0
        self.user_dao.exists.return_value = True
        assert_that(
            calling(self.service.remove_user).with_args(s.tenant_uuid, s.user_uuid),
            not_(raises(Exception)))

        self.tenant_dao.remove_user.return_value = 1
        self.user_dao.exists.return_value = True
        assert_that(
            calling(self.service.remove_user).with_args(s.tenant_uuid, s.user_uuid),
            not_(raises(Exception)))
