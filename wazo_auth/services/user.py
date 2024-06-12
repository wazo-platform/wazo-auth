# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import binascii
import hashlib
import logging
import os

from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService

logger = logging.getLogger(__name__)


class UnknownUserHash:
    def __eq__(self, other):
        return False

    def __ne__(self, other):
        return True


class UserService(BaseService):
    def __init__(self, dao, encrypter=None):
        super().__init__(dao)
        self._encrypter = encrypter or PasswordEncrypter()
        self._unknown_user_salt = os.urandom(self._encrypter._salt_len)
        # The unknown_user_hash will never be equal, whatever the user input is
        self._unknown_user_hash = UnknownUserHash()

    def add_policy(self, user_uuid, policy_uuid):
        self._dao.user.add_policy(user_uuid, policy_uuid)

    def change_password(self, user_uuid, old_password, new_password, reset=False):
        user = self.get_user(user_uuid)
        login = user['username']
        if not login:
            login = self._find_main_email(user)

        if not login:
            logger.warning('User %s does not have login (username or email)', user_uuid)
            raise exceptions.AuthenticationFailedException()

        if not self.verify_password(login, old_password, reset):
            raise exceptions.AuthenticationFailedException()

        salt, hash_ = self._encrypter.encrypt_password(new_password)
        self._dao.user.change_password(user_uuid, salt, hash_)

    def _find_main_email(self, user):
        for email in user['emails']:
            if email['main'] and email['confirmed']:
                return email['address']

    def delete_password(self, **kwargs):
        search_params = {k: v for k, v in kwargs.items() if v}
        identifier = list(search_params.values())[0]

        logger.debug('removing password for user %s', identifier)
        users = self._dao.user.list_(limit=1, **search_params)
        if not users:
            raise exceptions.UnknownUserException(identifier, details=kwargs)

        for user in users:
            self._dao.user.change_password(user['uuid'], salt=None, hash_=None)
            return user

    def count_groups(self, user_uuid, **kwargs):
        return self._dao.user.count_groups(user_uuid, **kwargs)

    def count_sessions(self, user_uuid, **kwargs):
        return self._dao.user.count_sessions(user_uuid, **kwargs)

    def count_policies(self, user_uuid, **kwargs):
        return self._dao.user.count_policies(user_uuid, **kwargs)

    def count_users(self, scoping_tenant_uuid=None, recurse=False, **kwargs):
        if scoping_tenant_uuid:
            kwargs['tenant_uuids'] = self._get_scoped_tenant_uuids(
                scoping_tenant_uuid, recurse
            )

        return self._dao.user.count(**kwargs)

    def delete_user(self, scoping_tenant_uuid, user_uuid):
        self.assert_user_in_subtenant(scoping_tenant_uuid, user_uuid)
        self._dao.user.delete(user_uuid)

    def get_acl(self, user_uuid):
        users = self._dao.user.list_(uuid=user_uuid, limit=1)
        acl = []
        for user in users:
            policies = self.list_policies(user['uuid'])
            for policy in policies:
                acl.extend(policy.acl)
        return acl

    def get_user(self, user_uuid, scoping_tenant_uuid=None):
        if scoping_tenant_uuid:
            self.assert_user_in_subtenant(scoping_tenant_uuid, user_uuid)

        users = self._dao.user.list_(uuid=user_uuid)
        for user in users:
            return user
        raise exceptions.UnknownUserException(user_uuid)

    def get_user_uuid_by_login(self, login):
        return self._dao.user.get_user_by_login(login).uuid

    def get_user_by_login(self, login):
        return self._dao.user.get_user_by_login(login)

    def list_groups(self, user_uuid, **kwargs):
        return self._dao.group.list_(user_uuid=user_uuid, **kwargs)

    def list_sessions(self, user_uuid, **kwargs):
        return self._dao.session.list_(user_uuid=user_uuid, **kwargs)

    def list_policies(self, user_uuid, **kwargs):
        return self._dao.policy.list_(user_uuid=user_uuid, **kwargs)

    def list_users(self, scoping_tenant_uuid=None, recurse=False, **kwargs):
        if scoping_tenant_uuid:
            kwargs['tenant_uuids'] = self._get_scoped_tenant_uuids(
                scoping_tenant_uuid, recurse
            )

        return self._dao.user.list_(**kwargs)

    def new_user(self, **kwargs):
        password = kwargs.pop('password', None)
        kwargs.setdefault('tenant_uuid', self.top_tenant_uuid)
        logger.info('creating a new user with params: %s', kwargs)
        if password:
            kwargs['salt'], kwargs['hash_'] = self._encrypter.encrypt_password(password)

        username = kwargs['username']
        if username and self._dao.user.login_exists(username):
            raise exceptions.UsernameLoginAlreadyExists(username)

        email = kwargs.get('email_address')
        if email and self._dao.user.login_exists(email):
            raise exceptions.EmailLoginAlreadyExists(email)

        user = self._dao.user.create(**kwargs)

        tenant_uuid = kwargs['tenant_uuid']
        wazo_all_users_group = self._dao.group.get_all_users_group(tenant_uuid)
        self._dao.group.add_user(wazo_all_users_group.uuid, user['uuid'])
        return user

    def remove_policy(self, user_uuid, policy_uuid):
        nb_deleted = self._dao.user.remove_policy(user_uuid, policy_uuid)
        if nb_deleted:
            return

        if not self._dao.user.exists(user_uuid):
            raise exceptions.UnknownUserException(user_uuid)

        if not self._dao.policy.exists(policy_uuid):
            raise exceptions.UnknownPolicyException(policy_uuid)

    def update(self, scoping_tenant_uuid, user_uuid, **kwargs):
        self.assert_user_in_subtenant(scoping_tenant_uuid, user_uuid)
        username = kwargs['username']
        if username and self._dao.user.login_exists(username, ignored_user=user_uuid):
            raise exceptions.UsernameLoginAlreadyExists(username)

        self._dao.user.update(user_uuid, **kwargs)
        return self.get_user(user_uuid)

    def update_emails(self, user_uuid, emails):
        for email in emails:
            address = email['address']
            if email and self._dao.user.login_exists(address, ignored_user=user_uuid):
                raise exceptions.EmailLoginAlreadyExists(address)

        return self._dao.user.update_emails(user_uuid, emails)

    def user_has_subtenant(self, user_uuid, tenant_uuid):
        user = self.get_user(user_uuid)
        return self._dao.tenant.is_subtenant(tenant_uuid, user['tenant_uuid'])

    def verify_password(self, login, password, reset=False):
        if reset:
            return True

        try:
            user = self._dao.user.get_user_by_login(login)
            hash_ = user.password_hash
            salt = user.password_salt
        except exceptions.UnknownLoginException:
            hash_ = self._unknown_user_hash
            salt = self._unknown_user_salt

        if not hash_ or not salt:
            hash_ = self._unknown_user_hash
            salt = self._unknown_user_salt

        return hash_ == self._encrypter.compute_password_hash(password, salt)

    def assert_user_in_subtenant(self, scoping_tenant_uuid, user_uuid):
        visible_tenants = self._dao.tenant.list_visible_tenants(scoping_tenant_uuid)
        tenant_uuids = [tenant.uuid for tenant in visible_tenants]
        user_exists = self._dao.user.exists(user_uuid, tenant_uuids=tenant_uuids)
        if not user_exists:
            raise exceptions.UnknownUserException(user_uuid)


class PasswordEncrypter:
    _salt_len = 64
    _hash_algo = 'sha512'
    _iterations = 250000

    def encrypt_password(self, password):
        salt = os.urandom(self._salt_len)
        hash_ = self.compute_password_hash(password, salt)
        return salt, hash_

    def compute_password_hash(self, password, salt):
        password_bytes = password.encode('utf-8')
        dk = hashlib.pbkdf2_hmac(
            self._hash_algo, password_bytes, salt, self._iterations
        )
        return binascii.hexlify(dk).decode('utf-8')
