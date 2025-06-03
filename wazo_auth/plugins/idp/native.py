# Copyright 2019-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from typing import TypedDict

from stevedore.extension import Extension

from wazo_auth.exceptions import InvalidUsernamePassword
from wazo_auth.interfaces import BaseAuthenticationBackend
from wazo_auth.services.tenant import TenantService
from wazo_auth.services.user import UserService

from .base import BaseIDP, BaseIDPDependencies

logger = logging.getLogger(__name__)


class Backends(TypedDict, total=False):
    wazo_user: Extension


class Dependencies(BaseIDPDependencies):
    backends: Backends
    user_service: UserService
    tenant_service: TenantService


class NativeIDP(BaseIDP):
    authentication_method = 'native'
    loaded = False

    _backend: BaseAuthenticationBackend

    def load(self, dependencies: Dependencies):
        logger.debug('Loading native idp plugin')
        super().load(dependencies)

        if 'wazo_user' not in dependencies['backends']:
            logger.error(
                'cannot load native idp plugin: missing wazo_auth.backends \'wazo_user\''
            )
            raise RuntimeError('missing wazo_user wazo_auth.backends extension')
        self._backend = dependencies['backends']['wazo_user'].obj

        self.loaded = True
        logger.debug('Native idp plugin loaded')

    def can_authenticate(self, args: dict) -> bool:
        # this method applies to request providing 'login' and 'password' credentials
        return 'login' in args and 'password' in args

    def get_backend(self, args: dict) -> BaseAuthenticationBackend:
        return self._backend

    def verify_auth(self, args: dict) -> tuple[BaseAuthenticationBackend, str]:
        assert self.loaded
        assert {'login', 'password'} <= args.keys()

        login = args['login']
        password = args['password']

        if not self._backend.verify_password(login, password, args):
            raise InvalidUsernamePassword(login)

        return self._backend, login
