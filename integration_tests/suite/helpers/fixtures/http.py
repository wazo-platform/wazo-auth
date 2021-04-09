# Copyright 2019-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import random
import string

import requests

from contextlib import contextmanager
from functools import wraps


def _random_string(length):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


def admin_client(**decorator_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            decorator_args.setdefault('tenant_name', _random_string(9))
            decorator_args.setdefault('username', _random_string(5))

            creator = self.client.users.new(username='creator', password='opensesame')
            policy = self.client.policies.new('tmp', acl=['auth.#'])
            self.client.users.add_policy(creator['uuid'], policy['uuid'])

            creator_client = self.new_auth_client(
                username='creator', password='opensesame'
            )
            creator_token = creator_client.token.new()
            creator_client.set_token(creator_token['token'])

            tenant = creator_client.tenants.new(
                name=decorator_args['tenant_name'], slug=decorator_args['tenant_slug']
            )

            username, password = decorator_args['username'], 'secret'
            created_user = creator_client.users.new(
                username=username, password=password, tenant_uuid=tenant['uuid']
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
            args = list(args) + [tenant]
            try:
                result = decorated(self, *args, **kwargs)
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
            token_args.setdefault('backend', 'wazo_user')
            token_args.setdefault('expiration', 5)
            if 'access_type' in token_args:
                token_args.setdefault('client_id', _random_string(20))
            username = token_args.pop('username')
            password = token_args.pop('password')
            client = self.new_auth_client(username, password)
            token = client.token.new(**token_args)
            if 'client_id' in token_args:
                token['client_id'] = token_args['client_id']
            args = list(args) + [token]
            try:
                result = decorated(self, *args, **kwargs)
            finally:
                try:
                    self.client.token.revoke(token['token'])
                except requests.HTTPError:
                    pass
            return result

        return wrapper

    return decorator


def user(**user_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            user_args.setdefault('username', _random_string(20))
            user_args.setdefault('password', _random_string(20))
            user = self.client.users.new(**user_args)
            args = list(args) + [user]
            try:
                result = decorated(self, *args, **kwargs)
            finally:
                try:
                    self.client.users.delete(user['uuid'])
                except requests.HTTPError:
                    pass
            return result

        return wrapper

    return decorator


def user_register(**user_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            user_args.setdefault('username', _random_string(20))
            user_args.setdefault('password', _random_string(20))
            username = user_args['username']
            user_args.setdefault('email_address', f'{username}@example.com')
            user = self.client.users.register(**user_args)
            args = list(args) + [user]
            try:
                result = decorated(self, *args, **kwargs)
            finally:
                try:
                    self.client.users.delete(user['uuid'])
                except requests.HTTPError:
                    pass
            return result

        return wrapper

    return decorator


@contextmanager
def config_managed_policy(db_client, policy, policy_args):
    if policy_args.get('config_managed'):
        policy_uuid = policy['uuid']
        with db_client.connect() as connection:
            connection.execute(
                f"UPDATE auth_policy set config_managed=true WHERE uuid = '{policy_uuid}'"
            )
    yield


def policy(**policy_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            policy_args.setdefault('name', _random_string(20))
            policy_args['acl'] = policy_args.get('acl') or []
            policy = self.client.policies.new(**policy_args)
            args = list(args) + [policy]
            try:
                with config_managed_policy(self.new_db_client(), policy, policy_args):
                    result = decorated(self, *args, **kwargs)
            finally:
                try:
                    self.client.policies.delete(policy['uuid'])
                except requests.HTTPError:
                    pass
            return result

        return wrapper

    return decorator


@contextmanager
def system_managed_group(db_client, group_uuid, group_args):
    if not group_args.get('system_managed'):
        yield
    else:
        with db_client.connect() as connection:
            connection.execute(
                f"UPDATE auth_group set system_managed=true WHERE uuid = '{group_uuid}'"
            )
        try:
            yield
        finally:
            with db_client.connect() as connection:
                connection.execute(
                    f"UPDATE auth_group set system_managed=false WHERE uuid = '{group_uuid}'"
                )


def group(**group_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            group_args.setdefault('name', _random_string(20))
            group = self.client.groups.new(**group_args)
            args = list(args) + [group]
            try:
                with system_managed_group(
                    self.new_db_client(), group['uuid'], group_args
                ):
                    result = decorated(self, *args, **kwargs)
            finally:
                try:
                    self.client.groups.delete(group['uuid'])
                except requests.HTTPError:
                    pass
            return result

        return wrapper

    return decorator


def session(**session_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            user_args = {'username': _random_string(20), 'password': 'pass'}
            if 'tenant_uuid' in session_args:
                user_args['tenant_uuid'] = session_args['tenant_uuid']
            mobile = session_args.get('mobile')
            token_args = {'session_type': 'mobile' if mobile else None}

            user = self.client.users.new(**user_args)
            client = self.new_auth_client(user_args['username'], user_args['password'])
            token = client.token.new(**token_args)
            session = self.client.users.get_sessions(user['uuid'])['items'][0]
            args = list(args) + [session]
            try:
                result = decorated(self, *args, **kwargs)
            finally:
                try:
                    self.client.users.delete(user['uuid'])
                    self.client.token.revoke(token['token'])
                except requests.HTTPError:
                    pass
            return result

        return wrapper

    return decorator
