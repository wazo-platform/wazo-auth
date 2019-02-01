# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import random
import string
import time
import uuid

from functools import wraps

from wazo_auth import exceptions
from wazo_auth.database import models


A_SALT = os.urandom(64)


def _random_string(length):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


def email(**email_args):
    email_args.setdefault('address', '{}@{}'.format(_random_string(5), _random_string(5)))

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


def token(**token_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            now = int(time.time())
            token = {
                'auth_id': 'test',
                'xivo_user_uuid': str(uuid.uuid4()),
                'xivo_uuid': str(uuid.uuid4()),
                'issued_t': now,
                'expire_t': now + token_args.get('expiration', 120),
                'acls': token_args.get('acls', []),
                'metadata': token_args.get('metadata', {}),
            }
            session_uuid = token_args.get('session_uuid')
            if not session_uuid:
                session_uuid = self._session_dao.create()
            token['session_uuid'] = session_uuid

            token_uuid = self._token_dao.create(token)
            token['uuid'] = token_uuid
            try:
                result = decorated(self, token, *args, **kwargs)
            finally:
                self._token_dao.delete(token_uuid)
                with self._session_dao.new_session() as s:
                    s.query(models.Session).filter(models.Session.uuid == session_uuid).delete()
            return result
        return wrapper
    return decorator


def session(**session_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            session_args.setdefault('uuid', str(uuid.uuid4()))
            session_uuid = self._session_dao.create(**session_args)
            session_args['uuid'] = session_uuid
            try:
                result = decorated(self, session_args, *args, **kwargs)
            finally:
                with self._session_dao.new_session() as s:
                    s.query(models.Session).filter(models.Session.uuid == session_uuid).delete()
            return result
        return wrapper
    return decorator


def group(**group_args):
    group_args.setdefault('name', _random_string(20))

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            group_args.setdefault('tenant_uuid', self.top_tenant_uuid)
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
    policy_args.setdefault('name', _random_string(20))
    policy_args['acl_templates'] = policy_args.get('acl_templates') or []
    policy_args['description'] = policy_args.get('description', '')

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            policy_args.setdefault('tenant_uuid', self.top_tenant_uuid)
            policy_uuid = self._policy_dao.create(**policy_args)
            try:
                result = decorated(self, policy_uuid, *args, **kwargs)
            finally:
                try:
                    self._policy_dao.delete(policy_uuid, [policy_args['tenant_uuid']])
                except exceptions.UnknownPolicyException:
                    pass
            return result
        return wrapper
    return decorator


def tenant(**tenant_args):
    tenant_args.setdefault('name', None)
    tenant_args.setdefault('phone', None)
    tenant_args.setdefault('contact_uuid', None)
    tenant_args.setdefault('address_id', None)

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
