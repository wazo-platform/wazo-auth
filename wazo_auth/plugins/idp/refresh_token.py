# Copyright 2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from collections.abc import Mapping
from typing import TypedDict

from stevedore.extension import Extension

from wazo_auth.exceptions import UnauthorizedAuthenticationMethod
from wazo_auth.interfaces import BaseAuthenticationBackend, IDPPlugin
from wazo_auth.services.tenant import TenantService
from wazo_auth.services.token import TokenService
from wazo_auth.services.user import UserService

from .base import BaseIDP, BaseIDPDependencies

logger = logging.getLogger(__name__)


class Backends(TypedDict, total=False):
    wazo_user: Extension


class Dependencies(BaseIDPDependencies):
    token_service: TokenService
    idp_plugins: dict[str, Extension]
    backends: Mapping[str, Extension]


class RefreshTokenIDP(BaseIDP):
    authentication_method = 'refresh_token'
    loaded = False
    _token_service: TokenService
    _user_service: UserService
    _tenant_service: TenantService

    def load(self, dependencies: Dependencies):
        logger.debug('Loading refresh idp plugin')
        super().load(dependencies)
        self._user_service = dependencies['user_service']
        self._tenant_service = dependencies['tenant_service']
        self._token_service = dependencies['token_service']
        self._backends = dependencies['backends']
        self._idp_plugins = dependencies['idp_plugins']
        self._native_idp = dependencies['native_idp']

        self.loaded = True
        logger.debug('refresh idp plugin loaded')

    def _get_user_auth_method(self, login):
        user = self._user_service.get_user_by_login(login)
        # TODO: can we push default auth method resolution to the db/dao layer?
        if user.authentication_method == 'default':
            tenant = self._tenant_service.get(None, user.tenant_uuid)
            authorized_method = tenant['default_authentication_method']
        else:
            authorized_method = user.authentication_method
        return authorized_method

    def can_authenticate(self, args: dict) -> bool:
        # this method applies to request providing 'login' and 'password' credentials
        return {'refresh_token', 'client_id'} <= args.keys()

    def get_backend(self, args: dict) -> BaseAuthenticationBackend:
        assert 'login' in args

        authorized_authentication_method = self._get_user_auth_method(args['login'])

        # TODO: these hardcoded mappings should be removed
        #  when those auth methods are implemented as IDP plugins
        if authorized_authentication_method == 'ldap':
            backend = self._backends['ldap_user'].obj
        else:
            # try and get backend from idp plugin
            try:
                idp_plugin: IDPPlugin = (
                    self._native_idp
                    if authorized_authentication_method == 'native'
                    else next(
                        plugin.obj
                        for name, plugin in self._idp_plugins.items()
                        if plugin.obj.authentication_method
                        == authorized_authentication_method
                    )
                )
            except StopIteration:
                logger.error(
                    'no idp plugin found for user authorized auth method %s',
                    authorized_authentication_method,
                )
                raise UnauthorizedAuthenticationMethod(
                    authorized_authentication_method,
                    'refresh_token',
                    args['login'],
                )

            if not hasattr(idp_plugin, 'get_backend'):
                logger.error(
                    'idp plugin %s does not implement a get_backend interface',
                    authorized_authentication_method,
                )
                raise UnauthorizedAuthenticationMethod(
                    authorized_authentication_method,
                    'refresh_token',
                    args['login'],
                )
            backend = idp_plugin.get_backend(args)

        return backend

    def verify_auth(self, args: dict) -> tuple[BaseAuthenticationBackend, str]:
        logger.debug('verifying refresh token login')
        assert self.loaded
        assert {'refresh_token', 'client_id'} <= args.keys()

        refresh_token = args['refresh_token']
        client_id = args['client_id']
        refresh_token_data = self._token_service.get_refresh_token_info(
            refresh_token,
            client_id,
        )

        login = refresh_token_data['login']
        args['login'] = login

        backend = self.get_backend(args)

        return backend, login
