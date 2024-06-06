# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


import logging

import marshmallow
from flask import redirect, request
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
            raise exceptions.SAMLParamException('RelayState and/or SAMLResponse')
        try:
            response = self._saml_service.process_auth_response(
                request.url, request.remote_addr, request.form
            )
            if response:
                logger.debug('ASC Post response: %s', response)
                return redirect(response)
            else:
                logger.warn('ACS response request failed: Context not found')
                raise exceptions.SAMLProcessingError('Context not found', 404)
        except UnknownPrincipal as excp:
            logger.info(f"UnknownPrincipal: {excp}")
            raise exceptions.SAMLProcessingError('Unknown principal')
        except UnsupportedBinding as excp:
            logger.info("UnsupportedBinding: %s", excp)
            raise exceptions.SAMLProcessingError('Unsupported binding')
        except VerificationError as err:
            logger.info("Verification error: %s", err)
            raise exceptions.SAMLProcessingError('Verification error')
        except SignatureError as err:
            logger.info("Signature error: %s", err)
            raise exceptions.SAMLProcessingError('Signature error')
        except Exception as err:
            logger.error("SAML unexpected error: %s", err)
            raise exceptions.SAMLProcessingError('Unexpected error')


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
