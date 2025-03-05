# Copyright 2019-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING

import stevedore

if TYPE_CHECKING:
    from wazo_auth.database.queries import DAO

from wazo_auth.exceptions import (
    InvalidUsernamePassword,
    NoMatchingSAMLSession,
    NoSuchBackendException,
    UnauthorizedAuthenticationMethod,
)
from wazo_auth.interfaces import BaseAuthenticationBackend, IDPPlugin
from wazo_auth.services.saml import SAMLService
from wazo_auth.services.tenant import TenantService

logger = logging.getLogger(__name__)


class AuthenticationService:
    def __init__(
        self,
        dao: DAO,
        backends: Mapping[str, stevedore.extension.Extension],
        tenant_service: TenantService,
        saml_service: SAMLService,
        idp_plugins: Mapping[str, stevedore.extension.Extension],
        native_idp: IDPPlugin,
    ):
        self._dao = dao
        self._backends = backends
        self._tenant_service = tenant_service
        self._saml_service = saml_service
        self._idp_plugins = idp_plugins
        self._native_idp = native_idp

    def verify_auth(self, args):
        if saml_session_id := args.get('saml_session_id'):
            backend, login = self.verify_saml(saml_session_id)
            args['login'] = login
        elif refresh_token := args.get('refresh_token'):
            backend, login = self.verify_refresh_token(refresh_token, args['client_id'])
            args['login'] = login
        elif 'domain_name' in args or 'tenant_id' in args:
            backend = self._get_backend('ldap_user')
            login = args.get('login', '')
            if not backend.verify_password(login, args.pop('password', ''), args):
                raise InvalidUsernamePassword(login)
            authorized_authentication_method = self._authorized_authentication_method(
                args['user_email']
            )
            if authorized_authentication_method != 'ldap':
                raise UnauthorizedAuthenticationMethod(
                    authorized_authentication_method, 'ldap', login
                )
        else:
            logger.info('Attempting to find idp plugin for login request')
            logger.debug('%d idp plugins available', len(self._idp_plugins))
            idp_name, idp_extension = next(
                (
                    (name, extension)
                    for name, extension in self._idp_plugins.items()
                    if extension.obj.can_authenticate(args)
                ),
                (None, None),
            )
            if idp_name is None:
                # NOTE: this is the only code path allowing the native auth to be used
                logger.debug(
                    'No available idp plugin can verify login request, falling back on native idp'
                )
                idp_plugin = self._native_idp
            else:
                logger.debug('idp plugin %s accepts to verify login request', idp_name)
                idp_plugin = idp_extension.obj

            # authentication failure would raise an exception that the API layer can handle
            backend, login = idp_plugin.verify_auth(args)

            logger.info(
                'Successfully authenticated login %s through authentication method %s',
                login,
                idp_plugin.authentication_method,
            )
            logger.debug(
                'authentication method %s authenticates login request with backend %s, login %s',
                idp_plugin.authentication_method,
                repr(backend),
                login,
            )

        return backend, login

    def verify_saml(self, saml_session_id):
        logger.debug('verifying SAML login')
        saml_login = self._saml_service.get_user_login(
            saml_session_id,
        )
        if not saml_login:
            raise NoMatchingSAMLSession(saml_session_id)

        if (
            authorized_authentication_method := self._authorized_authentication_method(
                saml_login
            )
        ) != 'saml':
            raise UnauthorizedAuthenticationMethod(
                authorized_authentication_method, 'saml', saml_login
            )

        # There's no SAML backend
        backend = self._get_backend('wazo_user')

        return backend, saml_login

    def verify_refresh_token(self, refresh_token, client_id):
        logger.debug('verifying refresh token login')
        refresh_token_data = self._dao.refresh_token.get(
            refresh_token,
            client_id,
        )
        login = refresh_token_data['login']
        authorized_authentication_method = self._authorized_authentication_method(login)
        if authorized_authentication_method == 'native':
            backend = self._get_backend('wazo_user')
        elif authorized_authentication_method == 'ldap':
            backend = self._get_backend('ldap_user')
        elif authorized_authentication_method == 'saml':
            backend = self._get_backend('wazo_user')
        else:
            raise UnauthorizedAuthenticationMethod(
                authorized_authentication_method, 'refresh_token', refresh_token
            )

        return backend, login

    def _get_backend(self, backend_name: str) -> BaseAuthenticationBackend:
        try:
            return self._backends[backend_name].obj
        except KeyError:
            logger.debug('backend not found: "%s"', backend_name)
            raise NoSuchBackendException(backend_name)

    def _authorized_authentication_method(self, login: str):
        user = self._dao.user.get_user_by_login(login)
        if user.authentication_method != 'default':
            return user.authentication_method
        tenant = self._tenant_service.get(None, user.tenant_uuid)
        return tenant['default_authentication_method']
