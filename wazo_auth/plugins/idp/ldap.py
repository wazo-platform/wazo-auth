# Copyright 2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from typing import TypedDict

from stevedore.extension import Extension

from wazo_auth.exceptions import InvalidUsernamePassword
from wazo_auth.interfaces import BaseAuthenticationBackend

from .base import BaseIDP, BaseIDPDependencies

logger = logging.getLogger(__name__)


class Backends(TypedDict, total=False):
    ldap_user: Extension


class Dependencies(BaseIDPDependencies):
    backends: Backends


class LDAPIDP(BaseIDP):
    authentication_method = 'ldap'
    loaded = False

    _backend: BaseAuthenticationBackend

    def load(self, dependencies: Dependencies):
        logger.debug('Loading ldap idp plugin')
        super().load(dependencies)

        if 'ldap_user' not in dependencies['backends']:
            logger.error(
                'cannot load ldap idp plugin: missing wazo_auth.backends \'ldap_user\''
            )
            raise RuntimeError('missing ldap_user wazo_auth.backends extension')

        self._backend = dependencies['backends']['ldap_user'].obj

        self.loaded = True
        logger.debug('ldap idp plugin loaded')

    def can_authenticate(self, args: dict) -> bool:
        return bool(
            {'login', 'password'} <= set(args)
            and {'domain_name', 'tenant_id'} & set(args)
        )

    def get_backend(self, args: dict) -> BaseAuthenticationBackend:
        return self._backend

    def verify_auth(self, args: dict) -> tuple[BaseAuthenticationBackend, str]:
        assert self.loaded
        assert {'login', 'password'} <= set(args)
        assert {'domain_name', 'tenant_id'} & set(args)

        ldap_login = args['login']
        password = args['password']

        logger.debug(
            'verifying LDAP login for (username=%s, domain_name=%s, tenant_id=%s)',
            ldap_login,
            args.get('domain_name'),
            args.get('tenant_id'),
        )

        if not self._backend.verify_password(ldap_login, password, args):
            # TODO: should use ldap-specific exception
            raise InvalidUsernamePassword(ldap_login)

        # TODO: avoid relying on mutable args here
        assert 'user_email' in args
        login = args['user_email']

        args['login'] = login

        return self._backend, login
