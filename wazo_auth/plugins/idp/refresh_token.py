# Copyright 2019-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from typing import TypedDict

from stevedore.extension import Extension

from wazo_auth.exceptions import InvalidLoginRequest, UnauthorizedAuthenticationMethod
from wazo_auth.interfaces import BaseAuthenticationBackend
from wazo_auth.services.token import TokenService

from .base import BaseIDP, BaseIDPDependencies

logger = logging.getLogger(__name__)


class Backends(TypedDict, total=False):
    wazo_user: Extension


class Dependencies(BaseIDPDependencies):
    token_service: TokenService


class RefreshTokenIDP(BaseIDP):
    authentication_method = 'refresh_token'
    loaded = False

    _backends: dict[str, Extension]
    _token_service: TokenService

    def load(self, dependencies: Dependencies):
        logger.debug('Loading refresh idp plugin')
        super().load(dependencies)
        self._token_service = dependencies['token_service']
        self._backends = dependencies['backends']

        self.loaded = True
        logger.debug('refresh idp plugin loaded')

    def can_authenticate(self, args: dict) -> bool:
        # this method applies to request providing 'login' and 'password' credentials
        return {'refresh_token', 'client_id'} <= args.keys()

    def _get_backend(self, auth_method: str, login: str) -> BaseAuthenticationBackend:
        # TODO: abstract away this auth method - backend
        # mapping to support arbitrary auth methods
        if auth_method == 'native':
            backend = self._backends['wazo_user'].obj
        elif auth_method == 'ldap':
            backend = self._backends['ldap_user'].obj
        elif auth_method == 'saml':
            backend = self._backends['wazo_user'].obj
        else:
            raise UnauthorizedAuthenticationMethod(
                auth_method,
                'refresh_token',
                login,
            )

        return backend

    def verify_auth(self, args: dict) -> tuple[BaseAuthenticationBackend, str]:
        logger.debug('verifying refresh token login')
        assert self.loaded

        if not {'refresh_token', 'client_id'} <= args.keys():
            raise InvalidLoginRequest(args)

        refresh_token = args['refresh_token']
        client_id = args['client_id']
        refresh_token_data = self._token_service.get_refresh_token_info(
            refresh_token,
            client_id,
        )

        login = refresh_token_data['login']
        authorized_authentication_method = self._get_user_auth_method(login)
        # backend depends on the user's auth method,
        # as refresh tokens are used in combination with other auth methods
        backend = self._get_backend(authorized_authentication_method, login)

        return backend, login
