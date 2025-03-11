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
    InvalidLoginRequest,
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
        refresh_token_idp: IDPPlugin,
    ):
        self._dao = dao
        self._backends = backends
        self._tenant_service = tenant_service
        self._saml_service = saml_service
        self._idp_plugins = idp_plugins
        self._native_idp = native_idp
        self._refresh_token_idp = refresh_token_idp

    def verify_auth(self, args):
        selected_authentication_method = None

        # check refresh token first, as it may be used along with other auth methods
        if self._refresh_token_idp.can_authenticate(args):
            backend, login = self._refresh_token_idp.verify_auth(args)
            args['login'] = login
            selected_authentication_method = 'refresh_token'
        elif saml_session_id := args.get('saml_session_id'):
            backend, login = self.verify_saml(saml_session_id)
            args['login'] = login
            selected_authentication_method = 'saml'
        elif 'domain_name' in args or 'tenant_id' in args:
            backend = self._get_backend('ldap_user')
            # TODO: cleanup "login" confusion.
            ldap_login = args.get(
                'login', ''
            )  # ldap username, not necessarily wazo username or email
            if not backend.verify_password(ldap_login, args.pop('password', ''), args):
                raise InvalidUsernamePassword(ldap_login)
            # TODO: avoid relying on mutable args
            assert 'user_email' in args
            login = args['user_email']
            selected_authentication_method = 'ldap'
        else:
            logger.info('Attempting to find idp plugin for login request')
            logger.debug('%d idp plugins available', len(self._idp_plugins))
            # search for appropriate plugin
            idp_name, idp_extension = None, None
            for name, extension in self._idp_plugins.items():
                logger.debug('Checking login request against idp plugin %s', name)
                try:
                    if extension.obj.can_authenticate(args):
                        idp_name, idp_extension = name, extension
                        break
                    else:
                        logger.debug(
                            'idp plugin %s cannot authenticate login request', name
                        )
                except Exception:
                    logger.exception(
                        'Unexpected error from idp plugin %s can_authenticate method',
                        name,
                    )
                    continue

            if idp_name is None:
                # NOTE: this is the only code path allowing the native auth to be used
                logger.debug(
                    'No available idp plugin can verify login request, falling back on native idp'
                )
                if self._native_idp.can_authenticate(args):
                    idp_plugin = self._native_idp
                else:
                    logger.info('Cannot authenticate login request with native idp')
                    raise InvalidLoginRequest(args)
            else:
                logger.debug('idp plugin %s accepts to verify login request', idp_name)
                idp_plugin = idp_extension.obj

            selected_authentication_method = idp_plugin.authentication_method

            # authentication failure should raise an exception that the API layer can handle
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

        # verify user authorized auth method
        assert selected_authentication_method
        authorized_authentication_method = self._authorized_authentication_method(login)
        logger.debug(
            'User (login=%s) authorized auth method is \'%s\'',
            login,
            authorized_authentication_method,
        )
        # NOTE: if method is refresh_token, refresh_token implementation takes care of
        #  verifying user for compatible auth method
        #  when selecting which wazo_auth.backend to use
        if (
            selected_authentication_method != 'refresh_token'
            and authorized_authentication_method != selected_authentication_method
        ):
            raise UnauthorizedAuthenticationMethod(
                authorized_authentication_method,
                selected_authentication_method,
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
