# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


import logging
from xml.etree import ElementTree

import marshmallow
from flask import make_response, request
from xivo.auth_verifier import required_acl

from wazo_auth import exceptions, http
from wazo_auth.exceptions import InvalidListParamException, SAMLConfigParameterException
from wazo_auth.flask_helpers import Tenant

from .schemas import saml_acs_url_template_schema, saml_config_schema

logger = logging.getLogger(__name__)


class SAMLConfig(http.AuthResource):
    def __init__(self, saml_config_service) -> None:
        self._saml_config_service = saml_config_service

    @required_acl('auth.backends.saml.read')
    def get(self):
        scoping_tenant: Tenant = Tenant.autodetect()
        try:
            if config := self._saml_config_service.get(scoping_tenant.uuid):
                return saml_config_schema.dump(obj=config), 200
        except exceptions.APIException as e:
            raise e
        except Exception as e:
            logger.exception(
                f"An error occurred while getting SAML config for tenant {scoping_tenant.uuid}."
            )
            raise SAMLConfigParameterException(
                scoping_tenant.uuid, f'Internal server error({e})', 500
            )

    @required_acl('auth.backends.saml.update')
    def post(self):
        scoping_tenant: Tenant = Tenant.autodetect()
        try:
            saml_config = saml_config_schema.load(request.form.to_dict())
        except marshmallow.ValidationError as e:
            raise InvalidListParamException.from_errors(e.messages)

        if 'metadata' not in request.files:
            raise SAMLConfigParameterException(
                scoping_tenant.uuid, 'No metadata file provided', 400
            )

        file = request.files['metadata']
        if file.filename == '':
            raise SAMLConfigParameterException(
                scoping_tenant.uuid, 'Empty metadata file provided', 400
            )

        try:
            idp_metadata: ElementTree.ElementTree = ElementTree.parse(file)
        except ElementTree.ParseError as e:
            raise SAMLConfigParameterException(
                scoping_tenant.uuid, f'Invalid XML ({e})', 400
            )

        try:
            config = self._saml_config_service.create(
                scoping_tenant.uuid, saml_config, idp_metadata
            )
            return saml_config_schema.dump(config), 200
        except exceptions.APIException as e:
            raise e
        except Exception as e:
            logger.exception(
                msg=(
                    "An error occurred while creating/updating SAML config "
                    f"for tenant {scoping_tenant.uuid}."
                )
            )
            raise SAMLConfigParameterException(
                scoping_tenant.uuid,
                f'Unexpected error while processing configuration ({e})',
                500,
            )

    @required_acl('auth.backends.saml.update')
    def put(self):
        scoping_tenant: Tenant = Tenant.autodetect()
        metadata = None
        args = saml_config_schema.load(request.form.to_dict(), partial=True)
        if 'metadata' in request.files:
            file = request.files['metadata']
            if file.filename == '':
                raise SAMLConfigParameterException(
                    scoping_tenant.uuid, 'Empty metadata file provided', 400
                )
            try:
                metadata = ElementTree.parse(file)
            except ElementTree.ParseError as e:
                raise SAMLConfigParameterException(
                    scoping_tenant.uuid, f'Invalid XML ({e})', 400
                )

        try:
            config = self._saml_config_service.update(
                scoping_tenant.uuid, args, metadata
            )
            return saml_config_schema.dump(config), 200
        except exceptions.APIException as e:
            raise e
        except Exception as e:
            logger.exception(
                msg=(
                    "An error occurred while creating/updating SAML config "
                    f"for tenant {scoping_tenant.uuid}."
                )
            )
            raise SAMLConfigParameterException(
                scoping_tenant.uuid,
                f'Unexpected error while processing configuration ({e})',
                500,
            )

    @required_acl('auth.backends.saml.delete')
    def delete(self):
        scoping_tenant: Tenant = Tenant.autodetect()
        try:
            self._saml_config_service.delete(scoping_tenant.uuid)
            return '', 204
        except exceptions.APIException as e:
            raise e
        except Exception as e:
            logger.exception(
                f"An error occurred while deleting SAML config for tenant {scoping_tenant.uuid}."
            )
            raise SAMLConfigParameterException(
                scoping_tenant.uuid, f'Internal server error({e})', 500
            )


class SAMLMetadata(http.AuthResource):
    def __init__(self, saml_config_service) -> None:
        self._saml_config_service = saml_config_service

    @required_acl('auth.backends.saml.read')
    def get(self):
        scoping_tenant: Tenant = Tenant.autodetect()
        try:
            if etree_metadata := self._saml_config_service.get_metadata(
                scoping_tenant.uuid
            ):
                response = make_response(ElementTree.tostring(etree_metadata))
                response.headers['Content-Type'] = 'application/xml'
                response.headers['Content-Disposition'] = 'attachment'
                return response
        except exceptions.APIException as e:
            raise e
        except Exception as e:
            logger.exception(
                f"An error occurred while getting SAML metadata for tenant {scoping_tenant.uuid}."
            )
            raise SAMLConfigParameterException(
                scoping_tenant.uuid, f'Internal server error({e})', 500
            )


class SAMLAcsUrlTemplate(http.AuthResource):
    def __init__(self, saml_config_service) -> None:
        self._saml_config_service = saml_config_service

    @required_acl('auth.backends.saml.read')
    def get(self):
        try:
            if url := self._saml_config_service.get_acs_url_template():
                return saml_acs_url_template_schema.dump(url), 200
        except exceptions.APIException as e:
            raise e
        except Exception as e:
            logger.exception("An error occurred while getting SAML ACS URL")
            raise SAMLConfigParameterException(
                'unknown tenant', f'Internal server error({e})', 500
            )
