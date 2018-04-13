# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import binascii
import hashlib
import logging
import os

from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService

logger = logging.getLogger(__name__)


class UserService(BaseService):

    def __init__(self, dao, tenant_tree, encrypter=None):
        super(UserService, self).__init__(dao)
        self._tenant_tree = tenant_tree
        self._encrypter = encrypter or PasswordEncrypter()

    def add_policy(self, user_uuid, policy_uuid):
        self._dao.user.add_policy(user_uuid, policy_uuid)

    def change_password(self, user_uuid, old_password, new_password, reset=False):
        user = self.get_user(user_uuid)
        if not self.verify_password(user['username'], old_password, reset):
            raise exceptions.AuthenticationFailedException()

        salt, hash_ = self._encrypter.encrypt_password(new_password)
        self._dao.user.change_password(user_uuid, salt, hash_)

    def delete_password(self, **kwargs):
        search_params = {k: v for k, v in kwargs.iteritems() if v}
        identifier = search_params.values()[0]

        logger.debug('removing password for user %s', identifier)
        users = self._dao.user.list_(limit=1, **search_params)
        if not users:
            raise exceptions.UnknownUserException(identifier, details=kwargs)

        for user in users:
            self._dao.user.change_password(user['uuid'], salt=None, hash_=None)
            return user

    def count_groups(self, user_uuid, **kwargs):
        return self._dao.user.count_groups(user_uuid, **kwargs)

    def count_policies(self, user_uuid, **kwargs):
        return self._dao.user.count_policies(user_uuid, **kwargs)

    def count_tenants(self, user_uuid, **kwargs):
        return len(self.list_tenants(user_uuid, **kwargs))

    def count_users(self, top_tenant_uuid, **kwargs):
        if top_tenant_uuid:
            recurse = kwargs.get('recurse')
            if recurse:
                kwargs['tenant_uuids'] = self._tenant_tree.list_nodes(top_tenant_uuid)
            else:
                kwargs['tenant_uuids'] = [top_tenant_uuid]

        return self._dao.user.count(**kwargs)

    def delete_user(self, top_tenant, user_uuid):
        self.assert_user_in_subtenant(top_tenant, user_uuid)
        self._dao.user.delete(user_uuid)

    def get_acl_templates(self, username):
        users = self._dao.user.list_(username=username, limit=1)
        acl_templates = []
        for user in users:
            policies = self.list_policies(user['uuid'])
            for policy in policies:
                acl_templates.extend(policy['acl_templates'])
        return acl_templates

    def get_user(self, user_uuid, top_tenant_uuid=None):
        if top_tenant_uuid:
            self.assert_user_in_subtenant(top_tenant_uuid, user_uuid)

        users = self._dao.user.list_(uuid=user_uuid)
        for user in users:
            return user
        raise exceptions.UnknownUserException(user_uuid)

    def list_groups(self, user_uuid, **kwargs):
        return self._dao.group.list_(user_uuid=user_uuid, **kwargs)

    def list_policies(self, user_uuid, **kwargs):
        return self._dao.policy.get(user_uuid=user_uuid, **kwargs)

    def list_tenants(self, user_uuid, **kwargs):
        tenant_uuid = self.get_user(user_uuid)['tenant_uuid']
        tenant_uuids = self._tenant_tree.list_nodes(tenant_uuid)
        return self._dao.tenant.list_(uuids=tenant_uuids, **kwargs)

    def list_users(self, **kwargs):
        top_tenant_uuid = kwargs.pop('top_tenant_uuid', None)
        if top_tenant_uuid:
            recurse = kwargs.get('recurse')
            if recurse:
                kwargs['tenant_uuids'] = self._tenant_tree.list_nodes(top_tenant_uuid)
            else:
                kwargs['tenant_uuids'] = [top_tenant_uuid]

        return self._dao.user.list_(**kwargs)

    def new_user(self, **kwargs):
        password = kwargs.pop('password', None)
        logger.info('creating a new user with params: %s', kwargs)  # log after poping the password
        if password:
            kwargs['salt'], kwargs['hash_'] = self._encrypter.encrypt_password(password)

        kwargs.setdefault('tenant_uuid', self._dao.tenant.find_top_tenant())
        user = self._dao.user.create(**kwargs)

        return user

    def remove_policy(self, user_uuid, policy_uuid):
        nb_deleted = self._dao.user.remove_policy(user_uuid, policy_uuid)
        if nb_deleted:
            return

        if not self._dao.user.exists(user_uuid):
            raise exceptions.UnknownUserException(user_uuid)

        if not self._dao.policy.exists(policy_uuid):
            raise exceptions.UnknownPolicyException(policy_uuid)

    def update(self, top_tenant_uuid, user_uuid, **kwargs):
        self.assert_user_in_subtenant(top_tenant_uuid, user_uuid)
        self._dao.user.update(user_uuid, **kwargs)
        return self.get_user(user_uuid)

    def update_emails(self, user_uuid, emails):
        return self._dao.user.update_emails(user_uuid, emails)

    def verify_password(self, username, password, reset=False):
        if reset:
            return True

        try:
            hash_, salt = self._dao.user.get_credentials(username)
        except exceptions.UnknownUsernameException:
            return False

        if not hash_ or not salt:
            return False

        return hash_ == self._encrypter.compute_password_hash(password, salt)

    def assert_user_in_subtenant(self, top_tenant_uuid, user_uuid):
        tenant_uuids = self._tenant_tree.list_nodes(top_tenant_uuid)
        user_exists = self._dao.user.exists(user_uuid, tenant_uuids=tenant_uuids)
        if not user_exists:
            raise exceptions.UnknownUserException(user_uuid)


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
