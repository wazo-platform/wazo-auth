# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# SPDX-License-Identifier: GPL-3.0+

import binascii
import hashlib
import logging
import os

from . import exceptions

logger = logging.getLogger(__name__)


class GroupService(object):

    def __init__(self, dao):
        self._dao = dao

    def count(self, **kwargs):
        return self._dao.group.count(**kwargs)

    def create(self, **kwargs):
        uuid = self._dao.group.create(**kwargs)
        return dict(uuid=uuid, **kwargs)

    def delete(self, group_uuid):
        return self._dao.group.delete(group_uuid)

    def get(self, group_uuid):
        matching_groups = self._dao.group.list_(uuid=group_uuid, limit=1)
        for group in matching_groups:
            return group
        raise exceptions.UnknownGroupException(group_uuid)

    def list_(self, **kwargs):
        return self._dao.group.list_(**kwargs)

    def update(self, group_uuid, **kwargs):
        return self._dao.group.update(group_uuid, **kwargs)


class PolicyService(object):

    def __init__(self, dao):
        self._dao = dao

    def add_acl_template(self, policy_uuid, acl_template):
        return self._dao.policy.associate_policy_template(policy_uuid, acl_template)

    def create(self, **kwargs):
        return self._dao.policy.create(**kwargs)

    def count(self, **kwargs):
        return self._dao.policy.count(**kwargs)

    def delete(self, policy_uuid):
        return self._dao.policy.delete(policy_uuid)

    def delete_acl_template(self, policy_uuid, acl_template):
        return self._dao.policy.dissociate_policy_template(policy_uuid, acl_template)

    def get(self, policy_uuid):
        matching_policies = self._dao.policy.get(uuid=policy_uuid)
        for policy in matching_policies:
            return policy
        raise exceptions.UnknownPolicyException(policy_uuid)

    def list(self, **kwargs):
        return self._dao.policy.get(**kwargs)

    def update(self, policy_uuid, **body):
        self._dao.policy.update(policy_uuid, **body)
        return dict(uuid=policy_uuid, **body)


class TenantService(object):

    def __init__(self, dao):
        self._dao = dao

    def add_user(self, tenant_uuid, user_uuid):
        return self._dao.tenant.add_user(tenant_uuid, user_uuid)

    def count_users(self, tenant_uuid, **kwargs):
        return self._dao.tenant.count_users(tenant_uuid, **kwargs)

    def count(self, **kwargs):
        return self._dao.tenant.count(**kwargs)

    def delete(self, uuid):
        return self._dao.tenant.delete(uuid)

    def get(self, uuid):
        tenants = self._dao.tenant.list_(uuid=uuid, limit=1)
        for tenant in tenants:
            return tenant
        raise exceptions.UnknownTenantException(uuid)

    def list_(self, **kwargs):
        return self._dao.tenant.list_(**kwargs)

    def list_users(self, tenant_uuid, **kwargs):
        return self._dao.user.list_(tenant_uuid=tenant_uuid, **kwargs)

    def new(self, **kwargs):
        uuid = self._dao.tenant.create(**kwargs)
        return dict(uuid=uuid, **kwargs)

    def remove_user(self, tenant_uuid, user_uuid):
        return self._dao.tenant.remove_user(tenant_uuid, user_uuid)


class UserService(object):

    def __init__(self, dao, encrypter=None):
        self._dao = dao
        self._encrypter = encrypter or PasswordEncrypter()

    def add_policy(self, user_uuid, policy_uuid):
        self._dao.user.add_policy(user_uuid, policy_uuid)

    def count_policies(self, user_uuid, **kwargs):
        return self._dao.user.count_policies(user_uuid, **kwargs)

    def count_tenants(self, user_uuid, **kwargs):
        return self._dao.user.count_tenants(user_uuid, **kwargs)

    def count_users(self, **kwargs):
        return self._dao.user.count(**kwargs)

    def delete_user(self, user_uuid):
        self._dao.user.delete(user_uuid)

    def get_acl_templates(self, username):
        users = self._dao.user.list_(username=username, limit=1)
        acl_templates = []
        for user in users:
            policies = self.list_policies(user['uuid'])
            for policy in policies:
                acl_templates.extend(policy['acl_templates'])
        return acl_templates

    def get_user(self, user_uuid):
        users = self._dao.user.list_(uuid=user_uuid)
        for user in users:
            return user
        raise exceptions.UnknownUserException(user_uuid)

    def list_policies(self, user_uuid, **kwargs):
        return self._dao.policy.get(user_uuid=user_uuid, **kwargs)

    def list_tenants(self, user_uuid, **kwargs):
        return self._dao.tenant.list_(user_uuid=user_uuid, **kwargs)

    def list_users(self, **kwargs):
        return self._dao.user.list_(**kwargs)

    def new_user(self, **kwargs):
        password = kwargs.pop('password')
        salt, hash_ = self._encrypter.encrypt_password(password)
        logger.info('creating a new user with params: %s', kwargs)  # log after poping the password
        # a confirmation email should be sent
        return self._dao.user.create(salt=salt, hash_=hash_, **kwargs)

    def remove_policy(self, user_uuid, policy_uuid):
        self._dao.user.remove_policy(user_uuid, policy_uuid)

    def verify_password(self, username, password):
        try:
            hash_, salt = self._dao.user.get_credentials(username)
        except exceptions.UnknownUsernameException:
            return False

        return hash_ == self._encrypter.compute_password_hash(password, salt)


class PasswordEncrypter(object):

    _salt_len = 64
    _hash_algo = 'sha512'
    _iterations = 250000

    def encrypt_password(self, password):
        salt = os.urandom(self._salt_len)
        hash_ = self.compute_password_hash(password, salt)
        return salt, hash_

    def compute_password_hash(self, password, salt):
        password_bytes = password.encode('utf-8')
        dk = hashlib.pbkdf2_hmac(self._hash_algo, password_bytes, salt, self._iterations)
        return binascii.hexlify(dk)
