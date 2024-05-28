# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


import logging
from datetime import datetime, timezone

import marshmallow
from flask import Response, redirect, request
from saml2.response import VerificationError
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding
from saml2.sigver import SignatureError

from wazo_auth import exceptions, http
from wazo_auth.services.saml import SAMLService

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
            raise exceptions.InvalidInputException('RelayState and/or SAMLResponse')
        try:
            response = self._saml_service.process_auth_response(
                request.url, request.remote_addr, request.form
            )
            if response:
                logger.debug('ASC Post response: %s', response)
                return redirect(response)
            else:
                logger.warn('ACS response request failed: Context not found')
                return self._format_failed_reply(404, 'Context not found')
        except UnknownPrincipal as excp:
            logger.info(f"UnknownPrincipal: {excp}")
            return self._format_failed_reply(500, 'Unknown principal')
        except UnsupportedBinding as excp:
            logger.info("UnsupportedBinding: %s", excp)
            return self._format_failed_reply(500, 'Unsupported binding')
        except VerificationError as err:
            logger.info("Verification error: %s", err)
            return self._format_failed_reply(500, 'Verification error')
        except SignatureError as err:
            logger.info("Signature error: %s", err)
            return self._format_failed_reply(500, 'Signature error')
        except Exception as err:
            logger.error("SAML unexpected error: %s", err)
            return self._format_failed_reply(500, 'Unexpected error')

    def _format_failed_reply(self, code: int, msg: str) -> Response:
        return Response(
            status=code,
            response={
                'reason': [msg],
                'timestamp': [datetime.now(timezone.utc)],
                'status_code': code,
            },
        )


class SAMLSSO(http.ErrorCatchingResource):
    def __init__(self, saml_service: SAMLService):
        self._saml_service = saml_service
        self._schema = SAMLSSOSchema()

    def post(self):
        try:
            args = self._schema.load(request.get_json())
        except marshmallow.ValidationError as e:
            for field in e.messages:
                logger.info(
                    f"SSO redirect failed because of missing or wrong value of parameter: {field}"
                )
                raise exceptions.InvalidInputException(field)
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
            return Response(
                status=500,
                response='SAML configuration missing or SAML client init failed',
            )
