# Copyright 2019-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from typing import TypedDict

from stevedore.extension import Extension

from wazo_auth.exceptions import (
    InvalidLoginRequest,
    InvalidUsernamePassword,
    UnauthorizedAuthenticationMethod,
)
from wazo_auth.interfaces import (
    BaseAuthenticationBackend,
    IDPPlugin,
    IDPPluginDependencies,
)
from wazo_auth.services.tenant import TenantService
from wazo_auth.services.user import UserService

logger = logging.getLogger(__name__)


class Backends(TypedDict, total=False):
    wazo_user: Extension


class Dependencies(IDPPluginDependencies):
    backends: Backends
    user_service: UserService
    tenant_service: TenantService


class NativeIDP(IDPPlugin):
    authentication_method = 'native'
    loaded = False

    _user_service: UserService
    _tenant_service: TenantService
    _backend: BaseAuthenticationBackend

    def _get_user_auth_method(self, login):
        user = self._user_service.get_user_by_login(login)
        # TODO: can we push default auth method resolution to the db/dao layer?
        if user.authentication_method == 'default':
            tenant = self._tenant_service.get(None, user.tenant_uuid)
            authorized_method = tenant['default_authentication_method']
        else:
            authorized_method = user.authentication_method
        return authorized_method

    def load(self, dependencies: Dependencies):
        logger.debug('Loading native idp plugin')
        self._user_service = dependencies['user_service']
        self._tenant_service = dependencies['tenant_service']

        if 'wazo_user' not in dependencies['backends']:
            logger.error(
                'cannot load native idp plugin: missing wazo_auth.backend \'wazo_user\''
            )
            raise RuntimeError('missing wazo_user wazo_auth.backend extension')
        self._backend = dependencies['backends']['wazo_user'].obj

        self.loaded = True
        logger.debug('Native idp plugin loaded')

    def can_authenticate(self, args: dict) -> bool:
        # this method applies to request providing 'login' and 'password' credentials
        return 'login' in args and 'password' in args

    def verify_auth(self, args: dict) -> tuple[BaseAuthenticationBackend, str]:
        assert self.loaded

        if not ({'login', 'password'} <= args.keys()):
            raise InvalidLoginRequest(args)

        login = args['login']
        password = args['password']

        # verify user auth method
        auth_method = self._get_user_auth_method(login)
        logger.debug('User \'%s\' has auth method: \'%s\'', login, auth_method)
        if auth_method != self.authentication_method:
            raise UnauthorizedAuthenticationMethod(
                auth_method, self.authentication_method, login
            )

        if not self._backend.verify_password(login, password, args):
            raise InvalidUsernamePassword(login)

        return self._backend, login
