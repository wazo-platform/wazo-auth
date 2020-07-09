# Copyright 2019-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import random
import string
import time
import uuid

from functools import wraps


A_SALT = os.urandom(64)


def _random_string(length):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


def address(**address_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            address_id = self._address_dao.new(**address_args)
            self.session.begin_nested()
            try:
                return decorated(self, address_id, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def email(**email_args):
    email_args.setdefault(
        'address', '{}@{}'.format(_random_string(5), _random_string(5))
    )

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            email_uuid = self._email_dao.create(**email_args)
            self.session.begin_nested()
            try:
                return decorated(self, email_uuid, *args, **kwargs)
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
            try:
                return decorated(self, auth_types, *args, **kwargs)
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
                'acls': token_args.get('acls', []),
                'metadata': token_args.get('metadata', {}),
                'user_agent': token_args.get('user_agent', ''),
                'remote_addr': token_args.get('remote_addr', ''),
            }
            session = token_args.get('session', {})

            token_uuid, session_uuid = self._token_dao.create(token, session)
            token['uuid'] = token_uuid
            token['session_uuid'] = session_uuid
            self.session.begin_nested()
            try:
                return decorated(self, token, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def group(**group_args):
    group_args.setdefault('name', _random_string(20))

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            group_args.setdefault('tenant_uuid', self.top_tenant_uuid)
            group_uuid = self._group_dao.create(**group_args)
            self.session.begin_nested()
            try:
                return decorated(self, group_uuid, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def policy(**policy_args):
    policy_args.setdefault('name', _random_string(20))
    policy_args['acl_templates'] = policy_args.get('acl_templates') or []
    policy_args['description'] = policy_args.get('description', '')

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            policy_args.setdefault('tenant_uuid', self.top_tenant_uuid)
            policy_uuid = self._policy_dao.create(**policy_args)
            self.session.begin_nested()
            try:
                return decorated(self, policy_uuid, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def tenant(**tenant_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            tenant_args.setdefault('name', None)
            tenant_args.setdefault('phone', None)
            tenant_args.setdefault('contact_uuid', None)
            tenant_args.setdefault('address_id', None)
            tenant_args.setdefault('parent_uuid', self.top_tenant_uuid)

            tenant_uuid = self._tenant_dao.create(**tenant_args)
            self.session.begin_nested()
            try:
                return decorated(self, tenant_uuid, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def user(**user_args):
    user_args.setdefault('username', _random_string(20))
    user_args.setdefault('email_address', '{}@example.com'.format(_random_string(50)))
    user_args.setdefault('hash_', _random_string(64))
    user_args.setdefault('salt', A_SALT)
    user_args.setdefault('firstname', _random_string(20))
    user_args.setdefault('lastname', _random_string(20))
    user_args.setdefault('purpose', 'user')
    user_args.setdefault('enabled', True)

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            user_args.setdefault('tenant_uuid', self.top_tenant_uuid)
            user_uuid = self._user_dao.create(**user_args)['uuid']
            self.session.begin_nested()
            try:
                return decorated(self, user_uuid, *args, **kwargs)
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
            try:
                return decorated(self, refresh_token, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator
