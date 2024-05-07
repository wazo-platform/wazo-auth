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
            response = self._saml_service.process_auth_response(
                request.url, request.remote_addr, request.form
            )
        except UnknownPrincipal as excp:
            logger.error(f"UnknownPrincipal: {excp}")
            resp = ServiceError(f"UnknownPrincipal: {excp}")
            return resp(self.environ, self.start_response)
        except UnsupportedBinding as excp:
            logger.error(
                f"UnsupportedBinding: {excp}",
            )
            resp = ServiceError(f"UnsupportedBinding: {excp}")
            return resp(self.environ, self.start_response)
        except VerificationError as err:
            logger.warn(f"Verification error: {err}")
            resp = ServiceError(f"Verification error: {err}")
            return resp(self.environ, self.start_response)
        except SignatureError as err:
            logger.warn(f"Signature error: {err}")
            resp = ServiceError(f"Signature error: {err}")
            return resp(self.environ, self.start_response)
        except Exception as err:
            logger.error(f"SAML unexpected error: {err}")
            resp = ServiceError(f"Other error: {err}")
            return resp(self.environ, self.start_response)

        logger.debug(f'ASC Post response: {response}')
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
            http_args = self._saml_service.prepare_redirect_response(
                request.form['saml_session_id'], request.form['redirect_url']
            )
            return Response(headers=http_args['headers'], status=http_args['status'])
        except Exception as excp:
            logger.error(f"Failed to process initial SAML SSO post because of: {excp}")
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
            login: Optional[str] = self._saml_service.get_user_login(
                args.get('saml_session_id')
            )
            backend_name = 'wazo_user'
            args = {
                'user_agent': request.headers.get('User-Agent', ''),
                'mobile': False,
                'remote_addr': request.remote_addr,
                'backend': backend_name,
            }
            token = self._token_service.new_token(
                self._backend[backend_name].obj, login[0], args
            )
            redacted_token_id = 'XXXXXXXX-XXXX-XXXX-XXXX-XXXX' + token.token[-8:]
            logger.info(
                (
                    'Successful login: {login} got token {redacted_id} from {remote_addr} '
                    'using agent "{user_agent}"'
                ).format(
                    login=login,
                    redacted_id=redacted_token_id,
                    remote_addr=args['remote_addr'],
                    user_agent=args['user_agent'],
                )
            )

            return {'data': token.to_dict()}, 200
        else:
            return Response(
                status=400,
                response='Session id missing',
            )
