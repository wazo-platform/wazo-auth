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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>

import os
import random
import string
import requests

from functools import wraps

from wazo_auth import exceptions


A_SALT = os.urandom(64)


def _random_string(length):
    return ''.join(random.choice(string.ascii_lowercase) for _ in xrange(length))


def http_tenant(**tenant_args):
    if 'name' not in tenant_args:
        tenant_args['name'] = _random_string(20)

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
    if 'email_address' not in user_args:
        user_args['email_address'] = '{}@example.com'.format(user_args['username'])

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
            group_uuid = self._group_crud.create(**group_args)
            try:
                result = decorated(self, group_uuid, *args, **kwargs)
            finally:
                try:
                    self._group_crud.delete(group_uuid)
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
            policy_uuid = self._policy_crud.create(**policy_args)
            try:
                result = decorated(self, policy_uuid, *args, **kwargs)
            finally:
                try:
                    self._policy_crud.delete(policy_uuid)
                except exceptions.UnknownPolicyException:
                    pass
            return result
        return wrapper
    return decorator


def tenant(**tenant_args):
    if 'name' not in tenant_args:
        tenant_args['name'] = _random_string(20)

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            tenant_uuid = self._tenant_crud.create(**tenant_args)
            try:
                result = decorated(self, tenant_uuid, *args, **kwargs)
            finally:
                try:
                    self._tenant_crud.delete(tenant_uuid)
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

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            user_uuid = self._user_crud.create(**user_args)
            try:
                result = decorated(self, user_uuid, *args, **kwargs)
            finally:
                try:
                    self._user_crud.delete(user_uuid)
                except exceptions.UnknownUserException:
                    pass
            return result
        return wrapper
    return decorator
