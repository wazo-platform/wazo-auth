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

    def new(self, **kwargs):
        return self._storage.tenant_create(**kwargs)


class UserService(object):

    def __init__(self, storage, encrypter=None):
        self._storage = storage
        self._encrypter = encrypter or PasswordEncrypter()

    def count_users(self, **kwargs):
        return self._storage.user_count(**kwargs)

    def delete_user(self, user_uuid):
        self._storage.user_delete(user_uuid)

    def get_user(self, user_uuid):
        users = self._storage.user_list(uuid=user_uuid)
        for user in users:
            return user
        raise exceptions.UnknownUserException(user_uuid)

    def list_users(self, **kwargs):
        return self._storage.user_list(**kwargs)

    def new_user(self, *args, **kwargs):
        password = kwargs.pop('password')
        salt, hash_ = self._encrypter.encrypt_password(password)
        logger.info('creating a new user with params: %s', kwargs)  # log after poping the password
        # a confirmation email should be sent
        return self._storage.user_create(*args, salt=salt, hash_=hash_, **kwargs)

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
