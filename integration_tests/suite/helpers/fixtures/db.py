# Copyright 2019-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import base64
import hashlib
import os
import random
import secrets
import string
import time
import uuid
from functools import wraps
from typing import Any

from saml2.saml import NameID

from wazo_auth.database import models
from wazo_auth.services.saml import SamlAuthContext, SamlSessionItem

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
            email_args.setdefault('address', f'{_random_string(5)}@{_random_string(5)}')

            def create_user():
                user_args = {
                    'username': _random_string(5),
                    'purpose': 'user',
                    'tenant_uuid': self.top_tenant_uuid,
                    'authentication_method': 'default',
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
                'refresh_token_uuid': token_args.get('refresh_token_uuid', None),
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
            group_args.setdefault('slug', group_args['name'])
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
            tenant_args.setdefault('default_authentication_method', 'native')

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
            user_args.setdefault('email_address', f'{_random_string(50)}@example.com')
            user_args.setdefault('hash_', _random_string(64))
            user_args.setdefault('salt', A_SALT)
            user_args.setdefault('firstname', _random_string(20))
            user_args.setdefault('lastname', _random_string(20))
            user_args.setdefault('purpose', 'user')
            user_args.setdefault('enabled', True)
            user_args.setdefault('tenant_uuid', self.top_tenant_uuid)
            user_args.setdefault('authentication_method', 'default')
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


def ldap_config(**ldap_config_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            ldap_config_args.setdefault('tenant_uuid', self.top_tenant_uuid)
            ldap_config_args.setdefault('host', 'localhost')
            ldap_config_args.setdefault('port', 386)
            ldap_config_args.setdefault(
                'user_base_dn', 'ou=people,dc=wazo-platform,dc=org'
            )
            ldap_config_args.setdefault('user_login_attribute', 'uid')
            ldap_config_args.setdefault('user_email_attribute', 'mail')
            ldap_config = self._ldap_config_dao.create(**ldap_config_args)
            self.session.begin_nested()
            args = list(args) + [ldap_config]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def saml_config(**saml_config_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            domain = self._domain_dao.get(saml_config_args['tenant_uuid'])
            saml_config_args.setdefault('domain_uuid', domain[0].uuid)
            saml_config_args.setdefault('acs_url', 'https://stack/api/0.1/saml/acs')
            saml_config_args.setdefault('entity_id', 'entity_id')
            saml_config_args.setdefault('idp_metadata', '<my_xml_data/>')

            saml_config = self._saml_config_dao.create(**saml_config_args)
            self.session.begin_nested()
            args = list(args) + [saml_config]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def saml_session(request_id, **session_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            session_id: str = session_args.get('session_id') or secrets.token_urlsafe(
                16
            )
            relay_state: str = (
                session_args.get('session_id')
                or base64.urlsafe_b64encode(
                    hashlib.sha256(session_id.encode()).digest()
                ).decode()
            )
            redirect_url = (
                session_args.get('redirect_url')
                or 'https://stack.wazo.local/api/0.1/saml/acs'
            )
            domain = session_args.get('domain') or 'example.com'
            auth_context = SamlAuthContext(
                saml_session_id=session_id,
                redirect_url=redirect_url,
                domain=domain,
                relay_state=relay_state,
            )

            item = SamlSessionItem(request_id, auth_context)
            self._saml_session_dao.create(item)
            self.session.begin_nested()
            args = list(args) + [item]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator


def saml_pysaml2_cache(name_id: NameID, **session_args):
    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            entity_id: str = session_args.get('entity_id') or secrets.token_urlsafe(16)
            info: dict[str, Any] = session_args.get('info') or {
                'ava': {
                    'givenName': ['Alice'],
                    'surname': ['Test'],
                    'name': ['alice@test.idp.com'],
                },
                'name_id': '2=urn%3Aoasis%3Anames%3Atc%3ASAML%3A1.1%3Anameid-format%3AemailAddress'
                + ',4=alice%40test.idp.com',
                'came_from': 'bldKO8ntPi1zLbHVgBwYuw',
                'authn_info': [
                    (
                        'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
                        [],
                        '2024-09-16T09:18:09.886Z',
                    )
                ],
                'session_index': '_4564564-3453df-3456345792a',
            }
            not_on_or_after = (
                session_args.get('not_on_or_after') or int(time.time()) + 3600
            )

            self._saml_pysaml2_cache_dao.set(name_id, entity_id, info, not_on_or_after)
            self.session.begin_nested()
            args = list(args) + [
                {
                    'name_id': name_id,
                    'entity_id': entity_id,
                    'info': info,
                    'not_on_or_after': not_on_or_after,
                }
            ]
            try:
                return decorated(self, *args, **kwargs)
            finally:
                self.session.rollback()

        return wrapper

    return decorator
