# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import os
import random
import string
import requests

from functools import wraps

from wazo_auth import exceptions


A_SALT = os.urandom(64)


def _random_string(length):
    return ''.join(random.choice(string.ascii_lowercase) for _ in xrange(length))


def email(**email_args):
    if 'address' not in email_args:
        email_args['address'] = '{}@{}'.format(_random_string(5), _random_string(5))

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            email_uuid = self._email_dao.create(**email_args)
            try:
                result = decorated(self, email_uuid, *args, **kwargs)
            finally:
                try:
                    self._email_dao.delete(email_uuid)
                except exceptions.UnknownEmailException:
                    pass
            return result
        return wrapper
    return decorator


def external_auth(*auth_types):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            self._external_auth_dao.enable_all(auth_types)
            try:
                result = decorated(self, auth_types, *args, **kwargs)
            finally:
                self._external_auth_dao.enable_all([])
            return result
        return wrapper
    return decorator


def http_tenant(**tenant_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            tenant = self.client.tenants.new(**tenant_args)
            try:
                result = decorated(self, tenant, *args, **kwargs)
            finally:
                try:
                    self.client.tenants.delete(tenant['uuid'])
                except requests.HTTPError:
                    pass
            return result
        return wrapper
    return decorator


def http_user(**user_args):
    if 'username' not in user_args:
        user_args['username'] = _random_string(20)
    if 'password' not in user_args:
        user_args['password'] = _random_string(20)

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            user = self.client.users.new(**user_args)
            try:
                result = decorated(self, user, *args, **kwargs)
            finally:
                try:
                    self.client.users.delete(user['uuid'])
                except requests.HTTPError:
                    pass
            return result
        return wrapper
    return decorator


def http_user_register(**user_args):
    if 'username' not in user_args:
        user_args['username'] = _random_string(20)
    if 'password' not in user_args:
        user_args['password'] = _random_string(20)
    if 'email_address' not in user_args:
        user_args['email_address'] = '{}@example.com'.format(user_args['username'])

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            user = self.client.users.register(**user_args)
            try:
                result = decorated(self, user, *args, **kwargs)
            finally:
                try:
                    self.client.users.delete(user['uuid'])
                except requests.HTTPError:
                    pass
            return result
        return wrapper
    return decorator


def http_policy(**policy_args):
    if 'name' not in policy_args:
        policy_args['name'] = _random_string(20)
    policy_args['acl_templates'] = policy_args.get('acl_templates') or []
    policy_args['description'] = policy_args.get('description', '')

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            policy = self.client.policies.new(**policy_args)
            try:
                result = decorated(self, policy, *args, **kwargs)
            finally:
                try:
                    self.client.policies.delete(policy['uuid'])
                except requests.HTTPError:
                    pass
            return result
        return wrapper
    return decorator


def http_group(**group_args):
    if 'name' not in group_args:
        group_args['name'] = _random_string(20)

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            group = self.client.groups.new(**group_args)
            try:
                result = decorated(self, group, *args, **kwargs)
            finally:
                try:
                    self.client.groups.delete(group['uuid'])
                except requests.HTTPError:
                    pass
            return result
        return wrapper
    return decorator


def group(**group_args):
    if 'name' not in group_args:
        group_args['name'] = _random_string(20)

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            group_uuid = self._group_dao.create(**group_args)
            try:
                result = decorated(self, group_uuid, *args, **kwargs)
            finally:
                try:
                    self._group_dao.delete(group_uuid)
                except exceptions.UnknownGroupException:
                    pass
            return result
        return wrapper
    return decorator


def policy(**policy_args):
    if 'name' not in policy_args:
        policy_args['name'] = _random_string(20)
    policy_args['acl_templates'] = policy_args.get('acl_templates') or []
    policy_args['description'] = policy_args.get('description', '')

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            policy_uuid = self._policy_dao.create(**policy_args)
            try:
                result = decorated(self, policy_uuid, *args, **kwargs)
            finally:
                try:
                    self._policy_dao.delete(policy_uuid)
                except exceptions.UnknownPolicyException:
                    pass
            return result
        return wrapper
    return decorator


def tenant(**tenant_args):
    # TODO: change the name to be None instead of a random string
    if 'name' not in tenant_args:
        tenant_args['name'] = _random_string(20)
    if 'phone' not in tenant_args:
        tenant_args['phone'] = None
    if 'contact' not in tenant_args:
        tenant_args['contact'] = None
    if 'address_id' not in tenant_args:
        tenant_args['address_id'] = None

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            tenant_uuid = self._tenant_dao.create(**tenant_args)
            try:
                result = decorated(self, tenant_uuid, *args, **kwargs)
            finally:
                try:
                    self._tenant_dao.delete(tenant_uuid)
                except exceptions.UnknownTenantException:
                    pass
            return result
        return wrapper
    return decorator


def user(**user_args):
    if 'username' not in user_args:
        user_args['username'] = _random_string(20)
    if 'email_address' not in user_args:
        user_args['email_address'] = '{}@example.com'.format(_random_string(50))
    if 'hash_' not in user_args:
        user_args['hash_'] = _random_string(64)
    if 'salt' not in user_args:
        user_args['salt'] = A_SALT
    if 'firstname' not in user_args:
        user_args['firstname'] = _random_string(20)
    if 'lastname' not in user_args:
        user_args['lastname'] = _random_string(20)

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            user_uuid = self._user_dao.create(**user_args)['uuid']
            try:
                result = decorated(self, user_uuid, *args, **kwargs)
            finally:
                try:
                    self._user_dao.delete(user_uuid)
                except exceptions.UnknownUserException:
                    pass
            return result
        return wrapper
    return decorator
