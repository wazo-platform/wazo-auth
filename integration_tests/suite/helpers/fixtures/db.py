# Copyright 2019-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import random
import string
import time
import uuid

from functools import wraps

from wazo_auth.database import models


A_SALT = os.urandom(64)


def _random_string(length):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


def address(**address_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            address_args.setdefault('tenant_uuid', self.top_tenant_uuid)
            address_id = self._address_dao.new(**address_args)
            self.session.begin_nested()
            args = list(args) + [address_id]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def email(**email_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            email_args.setdefault(
                'address', '{}@{}'.format(_random_string(5), _random_string(5))
            )

            def create_user():
                user_args = {
                    'username': _random_string(5),
                    'purpose': 'user',
                    'tenant_uuid': self.top_tenant_uuid,
                }
                user = self._user_dao.create(**user_args)
                return user['uuid']

            email_args.setdefault('user_uuid', create_user())

            email = models.Email(**email_args)
            self.session.add(email)
            self.session.flush()
            email_uuid = email.uuid
            self.session.begin_nested()
            args = list(args) + [email_uuid]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def external_auth(*auth_types):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            self._external_auth_dao.enable_all(auth_types)
            self.session.begin_nested()
            args = list(args) + [auth_types]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def external_auth_config(**auth_config):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            auth_config.setdefault('auth_type', 'auto-generated')
            auth_config.setdefault('data', 'random-data')
            data = self._external_auth_dao.create_config(**auth_config)
            self.session.begin_nested()
            args = list(args) + [data]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def user_external_auth(**user_auth):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            user_auth.setdefault('auth_type', 'auto-generated')
            user_auth.setdefault('data', 'random-data')
            data = self._external_auth_dao.create(**user_auth)
            self.session.begin_nested()
            args = list(args) + [data]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def token(**token_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            now = int(time.time())
            token = {
                'auth_id': token_args.get('auth_id', str(uuid.uuid4())),
                'pbx_user_uuid': str(uuid.uuid4()),
                'xivo_uuid': str(uuid.uuid4()),
                'issued_t': now,
                'expire_t': now + token_args.get('expiration', 120),
                'acl': token_args.get('acl', []),
                'metadata': token_args.get('metadata', {}),
                'user_agent': token_args.get('user_agent', ''),
                'remote_addr': token_args.get('remote_addr', ''),
            }
            session = token_args.get('session', {})

            token_uuid, session_uuid = self._token_dao.create(token, session)
            token['uuid'] = token_uuid
            token['session_uuid'] = session_uuid
            self.session.begin_nested()
            args = list(args) + [token]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def group(**group_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            group_args.setdefault('name', _random_string(20))
            group_args.setdefault('tenant_uuid', self.top_tenant_uuid)
            group_args.setdefault('system_managed', False)
            group_uuid = self._group_dao.create(**group_args)
            self.session.begin_nested()
            args = list(args) + [group_uuid]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def policy(**policy_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            policy_args.setdefault('name', _random_string(20))
            policy_args.setdefault('slug', _random_string(10))
            policy_args.setdefault('config_managed', False)
            policy_args['acl'] = policy_args.get('acl') or []
            policy_args['description'] = policy_args.get('description', '')
            policy_args.setdefault('tenant_uuid', self.top_tenant_uuid)
            policy_uuid = self._policy_dao.create(**policy_args)
            self.session.begin_nested()
            args = list(args) + [policy_uuid]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def tenant(**tenant_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            tenant_args.setdefault('name', None)
            tenant_args.setdefault('slug', None)
            tenant_args.setdefault('phone', None)
            tenant_args.setdefault('contact_uuid', None)
            tenant_args.setdefault('parent_uuid', self.top_tenant_uuid)

            tenant_uuid = self._tenant_dao.create(**tenant_args)
            self.session.begin_nested()
            args = list(args) + [tenant_uuid]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def user(**user_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            user_args.setdefault('username', _random_string(20))
            user_args.setdefault(
                'email_address', '{}@example.com'.format(_random_string(50))
            )
            user_args.setdefault('hash_', _random_string(64))
            user_args.setdefault('salt', A_SALT)
            user_args.setdefault('firstname', _random_string(20))
            user_args.setdefault('lastname', _random_string(20))
            user_args.setdefault('purpose', 'user')
            user_args.setdefault('enabled', True)
            user_args.setdefault('tenant_uuid', self.top_tenant_uuid)
            user_uuid = self._user_dao.create(**user_args)['uuid']
            self.session.begin_nested()
            args = list(args) + [user_uuid]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def refresh_token(**refresh_token_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            refresh_token = self._refresh_token_dao.create(refresh_token_args)
            self.session.begin_nested()
            args = list(args) + [refresh_token]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator
