# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


import logging
from typing import Optional

import marshmallow
from flask import Response, redirect, request
from saml2.httputil import ServiceError
from saml2.response import VerificationError
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding
from saml2.sigver import SignatureError

from wazo_auth import exceptions, http

from .schemas import SAMLSessionIdSchema

logger = logging.getLogger(__name__)


class SAMLACS(http.ErrorCatchingResource):
    def __init__(
        self,
        token_service,
        user_service,
        auth_service,
        saml_service,
        config,
        backend_proxy,
    ):
        self._token_service = token_service
        self._user_service = user_service
        self._auth_service = auth_service
        self._saml_service = saml_service
        self._config = config
        self._backend_proxy = backend_proxy

    def post(self):
        try:
            response = self._saml_service.processAuthResponse(
                request.url, request.remote_addr, request.form
            )
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
            logger.error("SAML unexpected error: %s" % err)
            resp = ServiceError(f"Other error: {err}")
            return resp(self.environ, self.start_response)

        logger.debug('ASC Post response: %s' % response)
        return redirect(response)


class SAMLSSO(http.ErrorCatchingResource):
    def __init__(
        self,
        token_service,
        user_service,
        auth_service,
        saml_service,
        config,
        wazo_user_backend,
    ):
        self._token_service = token_service
        self._user_service = user_service
        self._auth_service = auth_service
        self._saml_service = saml_service
        self._config = config
        self._backend = wazo_user_backend

    def post(self):
        try:
            http_args = self._saml_service.prepareRedirectResponse(
                request.form['saml_session_id'], request.form['redirect_url']
            )
            return Response(headers=http_args['headers'], status=http_args['status'])
        except Exception as excp:
            logger.error("Failed to process initial SAML SSO post because of: %s", excp)
            return Response(
                status=500,
                response='SAML configuration missing or SAML client init failed',
            )


class SAMLTOKEN(http.ErrorCatchingResource):
    def __init__(
        self,
        token_service,
        user_service,
        auth_service,
        saml_service,
        config,
        wazo_user_backend,
    ):
        self._token_service = token_service
        self._user_service = user_service
        self._auth_service = auth_service
        self._saml_service = saml_service
        self._config = config
        self._backend = wazo_user_backend

    def post(self):
        try:
            args = SAMLSessionIdSchema().load(request.get_json())
        except marshmallow.ValidationError as e:
            raise exceptions.UserParamException.from_errors(e.messages)

        if args.get('saml_session_id'):
            userLogin: Optional[str] = self._saml_service.getUserLogin(
                args.get('saml_session_id')
            )
            return {'token': userLogin}
        else:
            return Response(
                status=400,
                response='Session id missing',
            )

        # Do you SAML validation here
        # Find the user's email adress from the SAML document. The username could also
        # be used if Wazo and the identity provider are configured with the same username
        # backend_name = 'wazo_user'
        # args = {
        #     'user_agent': request.headers.get('User-Agent', ''),
        #     'mobile': True,
        #     'remote_addr': request.remote_addr,
        # }        try:
        # http_args = self._getSamlRequest(self._saml_client, self._saml_config)

        # The following headers are expected on the ACS request
        # User-Agent
        # Wazo-Session-Type
        # The following values should be added to the ACS payload by the Agent
        # backend: defaults to wazo_user
        # expiration: token validity in seconds
        # access_type: online or offline
        # client_id: required if access_type is offline to create a request token

        # token = self._token_service.new_token(
        #     self._backend_proxy.get(backend_name), login, args
        # )
        # return {'data': token.to_dict()}, 200
