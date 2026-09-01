# Copyright 2024-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


import logging
from typing import Any

import marshmallow
from flask import redirect, request
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from werkzeug.wrappers.response import Response

from wazo_auth import exceptions, http
from wazo_auth.services.saml import SAMLService
from wazo_auth.services.token import TokenService
from wazo_auth.token import Token

from .schemas import SAMLSSOSchema

logger = logging.getLogger(__name__)


class SAMLACS(http.ErrorCatchingResource):
    def __init__(self, saml_service: SAMLService):
        self._saml_service = saml_service

    def post(self):
        if (
            request.form.get('RelayState') is None
            or request.form.get('SAMLResponse') is None
        ):
            logger.info('ACS response request failed: Missing or wrong parameters')
            raise exceptions.SAMLParamException('RelayState and/or SAMLResponse')
        try:
            response: str | None = self._saml_service.process_auth_response(
                request.url, request.remote_addr, request.form
            )
            logger.debug('ASC Post response: %s', response)
            return redirect(response)
        except exceptions.SAMLProcessingErrorWithReturnURL as err:
            logger.info('SAML SSO answer processing failed, redirect with error')
            return redirect(err.redirect_url)
        except exceptions.SAMLProcessingError as err:
            logger.warning('SAML SSO answer processing failed')
            raise err
        except Exception as err:
            logger.exception("SAML unexpected error: %s", err)
            raise exceptions.SAMLProcessingError('Unexpected error')


class SAMLSSO(http.ErrorCatchingResource):
    def __init__(self, saml_service: SAMLService):
        self._saml_service = saml_service
        self._schema = SAMLSSOSchema()

    def post(self):
        try:
            args = self._schema.load(request.get_json(force=True))
        except marshmallow.ValidationError as e:
            for field in e.messages:
                logger.info(
                    f"SSO redirect failed because of missing or wrong value of parameter: {field}"
                )
                raise exceptions.SAMLParamException(field)
        try:
            location, saml_session_id = self._saml_service.prepare_redirect_response(
                args['redirect_url'],
                args['domain'],
            )
            return {
                'location': location,
                'saml_session_id': saml_session_id,
            }
        except Exception as excp:
            logger.error("Failed to process initial SAML SSO post because of: %s", excp)
            raise exceptions.SAMLConfigurationError(
                domain=args['domain'],
            )


class SAMLLogout(http.ErrorCatchingResource):
    def __init__(self, saml_service: SAMLService, token_service: TokenService):
        self._saml_service: SAMLService = saml_service
        self._token_service: TokenService = token_service

    def get(self):
        token = request.headers.get('X-Auth-Token') or request.args.get('token')
        token_data: Token = self._token_service.get(token, required_access=None)
        try:
            location = self._saml_service.process_logout_request(
                token_data,
            )

            self._token_service.remove_token(token)
            if refresh_token := token_data.refresh_token:
                self._token_service.delete_refresh_token_by_uuid(refresh_token)

            rer: dict[str, Any] = {'location': location}
            return rer
        except exceptions.SAMLException as e:
            raise e
        except Exception as excp:
            logger.exception(
                f'Unexpected error while processing the logout request: {excp}'
            )
            raise exceptions.SAMLProcessingError(excp)


class SAMLSLS(http.ErrorCatchingResource):
    def __init__(self, saml_service: SAMLService):
        self._saml_service: SAMLService = saml_service

    def get(self) -> Response:
        try:
            message = request.args.get('SAMLResponse')
            relay_state = request.args.get('RelayState')
            location = self._saml_service.process_logout_request_response(
                message, relay_state, BINDING_HTTP_REDIRECT
            )
            return redirect(location)
        except Exception as e:
            raise exceptions.SAMLProcessingError(
                f'Unable to process logout request response ({e})'
            )

    def post(self) -> Response:
        try:
            message = request.form.get('SAMLResponse')
            relay_state = request.form.get('RelayState')
            if not message or not relay_state:
                raise exceptions.SAMLParamException('SAMLResponse and/or RelayState')
            location = self._saml_service.process_logout_request_response(
                message, relay_state, BINDING_HTTP_POST
            )
            return redirect(location)
        except exceptions.SAMLParamException:
            raise
        except Exception as e:
            raise exceptions.SAMLProcessingError(
                f'Unable to process logout request response ({e})'
            )
