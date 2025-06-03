# Copyright 2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from typing import TypedDict

from stevedore.extension import Extension

from wazo_auth.exceptions import NoMatchingSAMLSession
from wazo_auth.interfaces import BaseAuthenticationBackend
from wazo_auth.services.saml import SAMLService

from .base import BaseIDP, BaseIDPDependencies

logger = logging.getLogger(__name__)


class Backends(TypedDict, total=False):
    wazo_user: Extension


class Dependencies(BaseIDPDependencies):
    backends: Backends
    saml_service: SAMLService


class SAMLIDP(BaseIDP):
    authentication_method = 'saml'
    loaded = False

    _backend: BaseAuthenticationBackend

    def load(self, dependencies: Dependencies):
        logger.debug('Loading saml idp plugin')
        super().load(dependencies)

        if 'wazo_user' not in dependencies['backends']:
            logger.error(
                'cannot load saml idp plugin: missing wazo_auth.backends \'wazo_user\''
            )
            raise RuntimeError('missing wazo_user wazo_auth.backends extension')
        self._backend = dependencies['backends']['wazo_user'].obj
        self._saml_service = dependencies['saml_service']

        self.loaded = True
        logger.debug('saml idp plugin loaded')

    def can_authenticate(self, args: dict) -> bool:
        return 'saml_session_id' in args

    def get_backend(self, args: dict) -> BaseAuthenticationBackend:
        return self._backend

    def verify_auth(self, args: dict) -> tuple[BaseAuthenticationBackend, str]:
        assert self.loaded
        assert 'saml_session_id' in args

        logger.debug('verifying SAML login')
        saml_session_id = args['saml_session_id']
        saml_login = self._saml_service.get_user_login(
            saml_session_id,
        )
        if not saml_login:
            raise NoMatchingSAMLSession(saml_session_id)

        args['login'] = saml_login

        return self._backend, saml_login
