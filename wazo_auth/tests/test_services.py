# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import assert_that, contains, calling, equal_to, not_, raises
from ..schemas import BaseSchema
from marshmallow import fields
from mock import Mock, patch, sentinel as s
from unittest import TestCase

from .. import exceptions, services
from ..database import queries
from ..database.queries import address, email, external_auth, group, policy, tenant, token, user


class BaseServiceTestCase(TestCase):

    def setUp(self):
        self.address_dao = Mock(address.AddressDAO)
        self.email_dao = Mock(email.EmailDAO)
        self.external_auth_dao = Mock(external_auth.ExternalAuthDAO)
        self.group_dao = Mock(group.GroupDAO)
        self.policy_dao = Mock(policy.PolicyDAO)
        self.tenant_dao = Mock(tenant.TenantDAO)
        self.token_dao = Mock(token.TokenDAO)
        self.user_dao = Mock(user.UserDAO)
        self.encrypter = Mock(services.PasswordEncrypter)
        self.encrypter.encrypt_password.return_value = s.salt, s.hash_

        self.dao = queries.DAO(
            address=self.address_dao,
            email=self.email_dao,
            external_auth=self.external_auth_dao,
            group=self.group_dao,
            policy=self.policy_dao,
            tenant=self.tenant_dao,
            token=self.token_dao,
            user=self.user_dao,
        )


class TestExternalAuthService(BaseServiceTestCase):

    class Auth1SafeFields(BaseSchema):

        scope = fields.List(fields.String)

    def setUp(self):
        super(TestExternalAuthService, self).setUp()
        self.service = services.ExternalAuthService(self.dao)

    def test_list_external_auth(self):
        # No safe model registered for any auth type
        self.external_auth_dao.list_.return_value = [
            {'type': 'auth_1', 'data': {'scope': ['scope'], 'token': 'supersecret'}, 'enabled': True},
            {'type': 'auth_2', 'data': {'scope': ['one', 'two', 42], 'password': 'l337'}, 'enabled': True},
        ]

        result = self.service.list_(s.user_uuid)
        assert_that(result, contains(
            {'type': 'auth_1', 'data': {}, 'enabled': True},
            {'type': 'auth_2', 'data': {}, 'enabled': True},
        ))

        # With a safe model for auth_1
        self.service.register_safe_auth_model('auth_1', self.Auth1SafeFields)
        result = self.service.list_(s.user_uuid)
        assert_that(result, contains(
            {'type': 'auth_1', 'data': {'scope': ['scope']}, 'enabled': True},
            {'type': 'auth_2', 'data': {}, 'enabled': True},
        ))

        # With data not matching the model fallback to {}
        self.external_auth_dao.list_.return_value = [
            {'type': 'auth_1', 'data': {'scope': 42, 'token': 'supersecret'}, 'enabled': True},
            {'type': 'auth_2', 'data': {'scope': ['one', 'two', 42], 'password': 'l337'}, 'enabled': True},
        ]
        result = self.service.list_(s.user_uuid)
        assert_that(result, contains(
            {'type': 'auth_1', 'data': {}, 'enabled': True},
            {'type': 'auth_2', 'data': {}, 'enabled': True},
        ))


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


class TestPolicyService(BaseServiceTestCase):

    def setUp(self):
        super(TestPolicyService, self).setUp()
        self.service = services.PolicyService(self.dao)

    def test_delete_acl_template(self):
        def when(nb_deleted, policy_exists=True):
            self.policy_dao.dissociate_policy_template.return_value = nb_deleted
            self.policy_dao.exists.return_value = policy_exists

        when(nb_deleted=0, policy_exists=False)
        assert_that(
            calling(self.service.delete_acl_template).with_args(s.policy_uuid, s.acl_template),
            raises(exceptions.UnknownPolicyException))

        when(nb_deleted=0)
        assert_that(
            calling(self.service.delete_acl_template).with_args(s.policy_uuid, s.acl_template),
            not_(raises(Exception)))

        when(nb_deleted=1)
        assert_that(
            calling(self.service.delete_acl_template).with_args(s.policy_uuid, s.acl_template),
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

    def test_delete_password(self):
        self.user_dao.list_.return_value = []
        assert_that(
            calling(self.service.delete_password).with_args(username=s.username, email_address=None),
            raises(exceptions.UnknownUserException))
        self.user_dao.list_.assert_called_once_with(username=s.username)

        user_uuid = '4a2c93b6-4045-4116-8d53-263e3eac83dd'
        self.user_dao.list_.return_value = [{'uuid': user_uuid}]

        self.service.delete_password(email_address=s.email_address)

        self.user_dao.change_password.assert_called_once_with(user_uuid, salt=None, hash_=None)

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
