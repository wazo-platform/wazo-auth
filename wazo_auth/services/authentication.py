# Copyright 2019-2024 The Wazo Authors  (see the AUTHORS file)
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
from wazo_auth.interfaces import BaseAuthenticationBackend
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
    ):
        self._dao = dao
        self._backends = backends
        self._tenant_service = tenant_service
        self._saml_service = saml_service

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
                raise UnauthorizedAuthenticationMethod(authorized_authentication_method)
        else:
            login = args.get('login', '')
            authorized_authentication_method = self._authorized_authentication_method(
                login
            )
            logger.debug('Verifying %s login', authorized_authentication_method)
            if authorized_authentication_method == 'native':
                backend = self._get_backend('wazo_user')
            else:
                raise UnauthorizedAuthenticationMethod(authorized_authentication_method)

            # There's no password verification when using a refresh token or SAML
            if not backend.verify_password(login, args.pop('password', ''), args):
                raise InvalidUsernamePassword(login)

        return backend, login

    def verify_saml(self, saml_session_id):
        logger.debug('verifying SAML login')
        saml_login = self._saml_service.get_user_login_and_remove_context(
            saml_session_id,
        )
        if not saml_login:
            raise NoMatchingSAMLSession(saml_session_id)

        if (
            authorized_authentication_method := self._authorized_authentication_method(
                saml_login
            )
        ) != 'saml':
            raise UnauthorizedAuthenticationMethod(authorized_authentication_method)

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
            raise UnauthorizedAuthenticationMethod(authorized_authentication_method)

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
