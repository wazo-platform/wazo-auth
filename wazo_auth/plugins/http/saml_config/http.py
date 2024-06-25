# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


import logging
from xml.etree import ElementTree

from flask import make_response, request
from xivo.auth_verifier import required_acl

from wazo_auth import exceptions
from wazo_auth.exceptions import SAMLConfigException
from wazo_auth.flask_helpers import Tenant
from wazo_auth.http import AuthResource

from .schemas import saml_acs_url_schema, saml_config_schema

logger = logging.getLogger(__name__)


class SAMLConfig(AuthResource):
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
            raise SAMLConfigException(500, f'Internal server error({e})', '500')

    def _validate_xml(self, file) -> ElementTree.ElementTree:
        try:
            return ElementTree.parse(file)
        except ElementTree.ParseError as e:
            raise SAMLConfigException(400, f'Invalid XML ({e})', '400')

    @required_acl('auth.backends.saml.update')
    def put(self):
        scoping_tenant: Tenant = Tenant.autodetect()
        saml_config = saml_config_schema.load(request.form.to_dict())
        if 'metadata' not in request.files:
            raise SAMLConfigException(400, 'No metadata file provided', '400')
        file = request.files['metadata']
        if file.filename == '':
            raise SAMLConfigException(400, 'Empty metadata file provided', '400')
        idp_metadata = self._validate_xml(file)
        try:
            config = self._saml_config_service.create_or_update(
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
            raise SAMLConfigException(
                500, f'Unexpected error while processing configuration ({e})', '500'
            )

    @required_acl('auth.backends.saml.delete')
    def delete(self):
        scoping_tenant: Tenant = Tenant.autodetect()
        try:
            if self._saml_config_service.delete(scoping_tenant.uuid):
                return '', 204
        except exceptions.APIException as e:
            raise e
        except Exception as e:
            logger.exception(
                f"An error occurred while deleting SAML config for tenant {scoping_tenant.uuid}."
            )
            raise SAMLConfigException(500, f'Internal server error({e})', '500')


class SAMLMetadata(AuthResource):
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
            raise SAMLConfigException(500, f'Internal server error({e})', '500')


class SAMLAcsUrl(AuthResource):
    def __init__(self, saml_config_service) -> None:
        self._saml_config_service = saml_config_service

    @required_acl('auth.backends.saml.read')
    def get(self):
        scoping_tenant: Tenant = Tenant.autodetect()
        try:
            if url := self._saml_config_service.get_acs_url(scoping_tenant.uuid):
                return saml_acs_url_schema.dump(url), 200
        except exceptions.APIException as e:
            raise e
        except Exception as e:
            logger.exception(
                f"An error occurred while getting SAML ACS URL for tenant {scoping_tenant.uuid}."
            )
            raise SAMLConfigException(500, f'Internal server error({e})', '500')

        logger.info(f'Returning SAML ACS URL {scoping_tenant.uuid}')
