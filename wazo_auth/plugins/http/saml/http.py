# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


import logging

from flask import Response, redirect, request
from saml2.httputil import ServiceError
from saml2.response import VerificationError
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding
from saml2.sigver import SignatureError

from wazo_auth import http

logger = logging.getLogger(__name__)


class SAMLACS(http.ErrorCatchingResource):
    def __init__(
        self,
        token_service,
        user_service,
        auth_service,
        saml_service,
        config,
    ):
        self._token_service = token_service
        self._user_service = user_service
        self._auth_service = auth_service
        self._saml_service = saml_service
        self._config = config

    def post(self):
        try:
            response = self._saml_service.process_auth_response(
                request.url, request.remote_addr, request.form
            )
        # TODO all error handling here need work. self.environ does not exists
        except UnknownPrincipal as excp:
            logger.error("UnknownPrincipal: %s", excp)
            resp = ServiceError(f"UnknownPrincipal: {excp}")
            return resp(self.environ, self.start_response)
        except UnsupportedBinding as excp:
            logger.error("UnsupportedBinding: %s", excp)
            resp = ServiceError(f"UnsupportedBinding: {excp}")
            return resp(self.environ, self.start_response)
        except VerificationError as err:
            logger.warn("Verification error: %s", err)
            resp = ServiceError(f"Verification error: {err}")
            return resp(self.environ, self.start_response)
        except SignatureError as err:
            logger.warn("Signature error: %s", err)
            resp = ServiceError(f"Signature error: {err}")
            return resp(self.environ, self.start_response)
        except Exception as err:
            logger.error("SAML unexpected error: %s", err)
            resp = ServiceError(f"Other error: {err}")
            return resp(self.environ, self.start_response)

        logger.debug('ASC Post response: %s', response)
        return redirect(response)


class SAMLSSO(http.ErrorCatchingResource):
    def __init__(
        self,
        token_service,
        user_service,
        auth_service,
        saml_service,
        config,
    ):
        self._token_service = token_service
        self._user_service = user_service
        self._auth_service = auth_service
        self._saml_service = saml_service
        self._config = config

    def post(self):
        try:
            http_args = self._saml_service.prepare_redirect_response(
                request.form['saml_session_id'],
                request.form['redirect_url'],
                request.form['tenant_id'],
            )
            return Response(headers=http_args['headers'], status=http_args['status'])
        except Exception as excp:
            logger.error("Failed to process initial SAML SSO post because of: %s", excp)
            return Response(
                status=500,
                response='SAML configuration missing or SAML client init failed',
            )
