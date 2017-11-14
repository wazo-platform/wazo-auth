# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import binascii
import hashlib
import logging
import os

from . import exceptions

logger = logging.getLogger(__name__)


class PolicyService(object):

    def __init__(self, storage):
        self._storage = storage

    def add_acl_template(self, policy_uuid, acl_template):
        return self._storage.add_policy_acl_template(policy_uuid, acl_template)

    def create(self, **kwargs):
        return self._storage.create_policy(**kwargs)

    def count(self, search, **ignored):
        return self._storage.count_policies(search)

    def delete(self, policy_uuid):
        return self._storage.delete_policy(policy_uuid)

    def delete_acl_template(self, policy_uuid, acl_template):
        return self._storage.delete_policy_acl_template(policy_uuid, acl_template)

    def get(self, policy_uuid):
        return self._storage.get_policy(policy_uuid)

    def list(self, **kwargs):
        return self._storage.list_policies(**kwargs)

    def update(self, policy_uuid, **body):
        self._storage.update_policy(policy_uuid, **body)
        return dict(uuid=policy_uuid, **body)


class TenantService(object):

    def __init__(self, storage):
        self._storage = storage

    def add_user(self, tenant_uuid, user_uuid):
        return self._storage.tenant_add_user(tenant_uuid, user_uuid)

    def count_users(self, tenant_uuid, **kwargs):
        return self._storage.tenant_count_users(tenant_uuid, **kwargs)

    def count(self, **kwargs):
        return self._storage.tenant_count(**kwargs)

    def delete(self, uuid):
        return self._storage.tenant_delete(uuid)

    def get(self, uuid):
        tenants = self._storage.tenant_list(uuid=uuid, limit=1)
        for tenant in tenants:
            return tenant
        raise exceptions.UnknownTenantException(uuid)

    def list_(self, **kwargs):
        return self._storage.tenant_list(**kwargs)

    def list_users(self, tenant_uuid, **kwargs):
        return self._storage.user_list(tenant_uuid=tenant_uuid, **kwargs)

    def new(self, **kwargs):
        return self._storage.tenant_create(**kwargs)

    def remove_user(self, tenant_uuid, user_uuid):
        return self._storage.tenant_remove_user(tenant_uuid, user_uuid)


class UserService(object):

    def __init__(self, storage, encrypter=None):
        self._storage = storage
        self._encrypter = encrypter or PasswordEncrypter()

    def add_policy(self, user_uuid, policy_uuid):
        self._storage.user_add_policy(user_uuid, policy_uuid)

    def count_policies(self, user_uuid, **kwargs):
        return self._storage.user_count_policies(user_uuid, **kwargs)

    def count_tenants(self, user_uuid, **kwargs):
        return self._storage.user_count_tenants(user_uuid, **kwargs)

    def count_users(self, **kwargs):
        return self._storage.user_count(**kwargs)

    def delete_user(self, user_uuid):
        self._storage.user_delete(user_uuid)

    def get_acl_templates(self, username):
        users = self._storage.user_list(username=username, limit=1)
        acl_templates = []
        for user in users:
            policies = self.list_policies(user['uuid'])
            for policy in policies:
                acl_templates.extend(policy['acl_templates'])
        return acl_templates

    def get_user(self, user_uuid):
        users = self._storage.user_list(uuid=user_uuid)
        for user in users:
            return user
        raise exceptions.UnknownUserException(user_uuid)

    def list_policies(self, user_uuid, **kwargs):
        return self._storage.user_list_policies(user_uuid, **kwargs)

    def list_tenants(self, user_uuid, **kwargs):
        return self._storage.user_list_tenants(user_uuid, **kwargs)

    def list_users(self, **kwargs):
        return self._storage.user_list(**kwargs)

    def new_user(self, *args, **kwargs):
        password = kwargs.pop('password')
        salt, hash_ = self._encrypter.encrypt_password(password)
        logger.info('creating a new user with params: %s', kwargs)  # log after poping the password
        # a confirmation email should be sent
        return self._storage.user_create(*args, salt=salt, hash_=hash_, **kwargs)

    def remove_policy(self, user_uuid, policy_uuid):
        self._storage.user_remove_policy(user_uuid, policy_uuid)

    def verify_password(self, username, password):
        try:
            hash_, salt = self._storage.user_get_credentials(username)
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
