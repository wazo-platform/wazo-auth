# Copyright 2019-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import random
import string
from contextlib import contextmanager
from functools import wraps

import requests


def _random_string(length):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


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
            client = self.make_auth_client(username, password)
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
                    self.client.tenants.delete(user['tenant_uuid'])
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
            old_token = self.client._token_id
            self.client.set_token(self.admin_token)
            policy = self.client.policies.new(**policy_args)
            self.client.set_token(old_token)
            args = list(args) + [policy]
            try:
                with config_managed_policy(self.database, policy, policy_args):
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
    if not group_args.get('read_only'):
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
            group_args.setdefault('slug', group_args['name'].replace('-', '_'))
            group = self.client.groups.new(**group_args)
            args = list(args) + [group]
            try:
                with system_managed_group(self.database, group['uuid'], group_args):
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
            client = self.make_auth_client(user_args['username'], user_args['password'])
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


def ldap_config(**ldap_config_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            ldap_config_args.setdefault('host', 'slapd')
            ldap_config_args.setdefault('port', 389)
            ldap_config_args.setdefault(
                'user_base_dn', 'ou=people,dc=wazo-platform,dc=org'
            )
            ldap_config_args.setdefault('user_login_attribute', 'uid')
            ldap_config_args.setdefault('user_email_attribute', 'mail')

            tenant_uuid = ldap_config_args.get('tenant_uuid', self.top_tenant_uuid)
            ldap_config = self.client.ldap_config.update(
                ldap_config_args,
                tenant_uuid=tenant_uuid,
            )
            args = list(args) + [ldap_config]
            try:
                result = decorated(self, *args, **kwargs)
            finally:
                try:
                    self.client.ldap_config.delete(tenant_uuid=tenant_uuid)
                except requests.HTTPError:
                    pass
            return result

        return wrapper

    return decorator
