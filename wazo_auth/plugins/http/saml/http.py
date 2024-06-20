# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


import logging

import marshmallow
from flask import redirect, request

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
