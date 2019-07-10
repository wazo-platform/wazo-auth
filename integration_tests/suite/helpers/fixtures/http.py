# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import random
import string

import requests

from functools import wraps


def _random_string(length):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


def admin_client(**decorator_args):
    decorator_args.setdefault('tenant_name', _random_string(9))
    decorator_args.setdefault('username', _random_string(5))

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            creator = self.client.users.new(username='creator', password='opensesame')
            policy = self.client.policies.new('tmp', acl_templates=['auth.#'])
            self.client.users.add_policy(creator['uuid'], policy['uuid'])

            creator_client = self.new_auth_client(username='creator', password='opensesame')
            creator_token = creator_client.token.new()
            creator_client.set_token(creator_token['token'])

            tenant = creator_client.tenants.new(name=decorator_args['tenant_name'])

            username, password = decorator_args['username'], 'secret'
            created_user = creator_client.users.new(
                username=username,
                password=password,
                tenant_uuid=tenant['uuid'],
            )

            created_client = self.new_auth_client(username=username, password=password)
            created_token = created_client.token.new()
            created_client.set_token(created_token['token'])

            self.client.users.delete(creator['uuid'])
            self.client.policies.delete(policy['uuid'])

            result = decorated(self, created_client, *args, **kwargs)

            self.client.users.delete(created_user['uuid'])
            self.client.tenants.delete(tenant['uuid'])

            return result
        return wrapper
    return decorator


def tenant(**tenant_args):
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


def token(**token_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            username = token_args.pop('username')
            password = token_args.pop('password')
            client = self.new_auth_client(username, password)
            token = client.token.new(**token_args)
            try:
                result = decorated(self, token, *args, **kwargs)
            finally:
                try:
                    self.client.token.revoke(token['token'])
                except requests.HTTPError:
                    pass
            return result
        return wrapper
    return decorator


def user(**user_args):
    user_args.setdefault('username', _random_string(20))
    user_args.setdefault('password', _random_string(20))

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


def user_register(**user_args):
    user_args.setdefault('username', _random_string(20))
    user_args.setdefault('password', _random_string(20))
    user_args.setdefault('email_address', '{}@example.com'.format(user_args['username']))

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


def policy(**policy_args):
    policy_args.setdefault('name', _random_string(20))
    policy_args['acl_templates'] = policy_args.get('acl_templates') or []

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


def group(**group_args):
    group_args.setdefault('name', _random_string(20))

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


def session(**session_args):
    user_args = {'username': _random_string(20), 'password': 'pass'}
    if 'tenant_uuid' in session_args:
        user_args['tenant_uuid'] = session_args['tenant_uuid']
    token_args = {'session_type': 'mobile' if session_args.get('mobile') else None}

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            user = self.client.users.new(**user_args)
            client = self.new_auth_client(user_args['username'], user_args['password'])
            token = client.token.new(**token_args)
            session = self.client.users.get_sessions(user['uuid'])['items'][0]
            try:
                result = decorated(self, session, *args, **kwargs)
            finally:
                try:
                    self.client.users.delete(user['uuid'])
                    self.client.token.revoke(token['token'])
                except requests.HTTPError:
                    pass
            return result
        return wrapper
    return decorator
