# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import assert_that, calling, equal_to, not_, raises
from mock import Mock, patch, sentinel as s
from unittest import TestCase

from .. import database, exceptions, services


class BaseServiceTestCase(TestCase):

    def setUp(self):
        self.external_auth_dao = Mock(database._ExternalAuthDAO)
        self.group_dao = Mock(database._GroupDAO)
        self.policy_dao = Mock(database._PolicyDAO)
        self.tenant_dao = Mock(database._TenantDAO)
        self.token_dao = Mock(database._TokenDAO)
        self.user_dao = Mock(database._UserDAO)
        self.encrypter = Mock(services.PasswordEncrypter)
        self.encrypter.encrypt_password.return_value = s.salt, s.hash_

        self.dao = database.DAO(
            self.policy_dao,
            self.token_dao,
            self.user_dao,
            self.tenant_dao,
            self.group_dao,
            self.external_auth_dao,
        )


class TestGroupService(BaseServiceTestCase):

    def setUp(self):
        super(TestGroupService, self).setUp()
        self.service = services.GroupService(self.dao)

    def test_remove_policy(self):
        def when(nb_deleted, group_exists=True, policy_exists=True):
            self.group_dao.remove_policy.return_value = nb_deleted
            self.group_dao.exists.return_value = group_exists
            self.policy_dao.exists.return_value = policy_exists

        when(nb_deleted=0, group_exists=False)
        assert_that(
            calling(self.service.remove_policy).with_args(s.group_uuid, s.policy_uuid),
            raises(exceptions.UnknownGroupException))

        when(nb_deleted=0, policy_exists=False)
        assert_that(
            calling(self.service.remove_policy).with_args(s.group_uuid, s.policy_uuid),
            raises(exceptions.UnknownPolicyException))

        when(nb_deleted=0)
        assert_that(
            calling(self.service.remove_policy).with_args(s.group_uuid, s.policy_uuid),
            not_(raises(Exception)))

        when(nb_deleted=1)
        assert_that(
            calling(self.service.remove_policy).with_args(s.group_uuid, s.policy_uuid),
            not_(raises(Exception)))

    def test_remove_user(self):
        def when(nb_deleted, group_exists=True, user_exists=True):
            self.group_dao.remove_user.return_value = nb_deleted
            self.group_dao.exists.return_value = group_exists
            self.user_dao.exists.return_value = user_exists

        when(nb_deleted=0, group_exists=False)
        assert_that(
            calling(self.service.remove_user).with_args(s.group_uuid, s.user_uuid),
            raises(exceptions.UnknownGroupException))

        when(nb_deleted=0, user_exists=False)
        assert_that(
            calling(self.service.remove_user).with_args(s.group_uuid, s.user_uuid),
            raises(exceptions.UnknownUserException))

        when(nb_deleted=0)
        assert_that(
            calling(self.service.remove_user).with_args(s.group_uuid, s.user_uuid),
            not_(raises(Exception)))

        when(nb_deleted=1)
        assert_that(
            calling(self.service.remove_user).with_args(s.group_uuid, s.user_uuid),
            not_(raises(Exception)))


class TestUserService(BaseServiceTestCase):

    def setUp(self):
        super(TestUserService, self).setUp()
        self.service = services.UserService(self.dao, encrypter=self.encrypter)

    def test_change_password(self):
        self.user_dao.list_.return_value = []
        assert_that(
            calling(self.service.change_password).with_args(s.uuid, s.old, s.new),
            raises(exceptions.UnknownUserException))

        self.user_dao.list_.return_value = [{'username': 'foobar'}]
        with patch.object(self.service, 'verify_password', return_value=False):
            assert_that(
                calling(self.service.change_password).with_args(s.uuid, s.old, s.new),
                raises(exceptions.AuthenticationFailedException))

        self.user_dao.list_.return_value = [{'username': 'foobar'}]
        with patch.object(self.service, 'verify_password', return_value=True):
            self.service.change_password(s.uuid, s.old, s.new)

        self.user_dao.change_password.assert_called_once_with(s.uuid, s.salt, s.hash_)

    def test_remove_policy(self):
        def when(nb_deleted, user_exists=True, policy_exists=True):
            self.user_dao.remove_policy.return_value = nb_deleted
            self.user_dao.exists.return_value = user_exists
            self.policy_dao.exists.return_value = policy_exists

        when(nb_deleted=0, user_exists=False)
        assert_that(
            calling(self.service.remove_policy).with_args(s.user_uuid, s.policy_uuid),
            raises(exceptions.UnknownUserException))

        when(nb_deleted=0, policy_exists=False)
        assert_that(
            calling(self.service.remove_policy).with_args(s.user_uuid, s.policy_uuid),
            raises(exceptions.UnknownPolicyException))

        when(nb_deleted=0)
        assert_that(
            calling(self.service.remove_policy).with_args(s.user_uuid, s.policy_uuid),
            not_(raises(Exception)))

        when(nb_deleted=1)
        assert_that(
            calling(self.service.remove_policy).with_args(s.user_uuid, s.policy_uuid),
            not_(raises(Exception)))

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

        result = self.service.new_user(**params)

        self.user_dao.create.assert_called_once_with(**expected_db_params)
        assert_that(result, equal_to(self.user_dao.create.return_value))


class TestTenantService(BaseServiceTestCase):

    def setUp(self):
        super(TestTenantService, self).setUp()
        self.service = services.TenantService(self.dao)

    def test_remove_user(self):
        def when(nb_deleted, tenant_exists=True, user_exists=True):
            self.tenant_dao.remove_user.return_value = nb_deleted
            self.tenant_dao.exists.return_value = tenant_exists
            self.user_dao.exists.return_value = user_exists

        when(nb_deleted=0, tenant_exists=False)
        assert_that(
            calling(self.service.remove_user).with_args(s.tenant_uuid, s.user_uuid),
            raises(exceptions.UnknownTenantException))

        when(nb_deleted=0, user_exists=False)
        assert_that(
            calling(self.service.remove_user).with_args(s.tenant_uuid, s.user_uuid),
            raises(exceptions.UnknownUserException))

        when(nb_deleted=0)
        assert_that(
            calling(self.service.remove_user).with_args(s.tenant_uuid, s.user_uuid),
            not_(raises(Exception)))

        when(nb_deleted=1)
        assert_that(
            calling(self.service.remove_user).with_args(s.tenant_uuid, s.user_uuid),
            not_(raises(Exception)))
