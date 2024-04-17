# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from flask import Response, request
from saml2 import BINDING_HTTP_REDIRECT, element_to_extension_element, xmldsig
from saml2.client import Saml2Client
from saml2.config import Config as SAMLConfig
from saml2.extension.pefim import SPCertEnc
from saml2.s_utils import rndstr
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.samlp import Extensions

from wazo_auth import http

logger = logging.getLogger(__name__)


class SAMLACS(http.ErrorCatchingResource):
    def __init__(
        self, token_service, user_service, auth_service, config, backend_proxy
    ):
        self._token_service = token_service
        self._user_service = user_service
        self._auth_service = auth_service
        self._config = (
            config  # Can be used to access to content of the configuration files
        )
        self._backend_proxy = backend_proxy

    def post(self):
        # Do you SAML validation here
        # Find the user's email adress from the SAML document. The username could also
        # be used if Wazo and the identity provider are configured with the same username
        login = email_address = 'alice@wazo.io'
        backend_name = 'wazo_user'
        args = {
            'user_agent': request.headers.get('User-Agent', ''),
            'login': email_address,
            'mobile': True,
            'remote_addr': request.remote_addr,
        }

        # The following headers are expected on the ACS request
        # User-Agent
        # Wazo-Session-Type
        # The following values should be added to the ACS payload by the Agent
        # backend: defaults to wazo_user
        # expiration: token validity in seconds
        # access_type: online or offline
        # client_id: required if access_type is offline to create a request token

        token = self._token_service.new_token(
            self._backend_proxy.get(backend_name), login, args
        )
        return {'data': token.to_dict()}, 200


class SAMLSSO(http.ErrorCatchingResource):
    def __init__(
        self, token_service, user_service, auth_service, config, wazo_user_backend
    ):
        self._token_service = token_service
        self._user_service = user_service
        self._auth_service = auth_service
        self._config = config
        self._backend = wazo_user_backend

    def _getSamlRequest(self, saml_client, saml_config):
        idps = saml_client.metadata.identity_providers()

        # just single IDP IDP supported
        entity_id = idps[0]

        # Picks a binding to use for sending the Request to the IDP
        _binding, destination = saml_client.pick_binding(
            "single_sign_on_service",
            [BINDING_HTTP_REDIRECT],
            "idpsso",
            entity_id=entity_id,
        )
        logger.debug("binding: %s, destination: %s", _binding, destination)
        # Binding here is the response binding that is which binding the
        # IDP should use to return the response.
        acs = saml_client.config.getattr("endpoints", "sp")[
            "assertion_consumer_service"
        ]
        # just pick one
        return_binding = acs[0]

        extensions = None
        if saml_client.config.generate_cert_func is not None:
            cert_str, req_key_str = saml_client.config.generate_cert_func()
            spcertenc = SPCertEnc(
                x509_data=xmldsig.X509Data(
                    x509_certificate=xmldsig.X509Certificate(text=cert_str)
                )
            )
            extensions = Extensions(
                extension_elements=[element_to_extension_element(spcertenc)]
            )

        req_id, req = saml_client.create_authn_request(
            destination,
            binding=return_binding,
            extensions=extensions,
            nameid_format=NAMEID_FORMAT_PERSISTENT,
        )
        _rstate = rndstr()
        http_args = saml_client.apply_binding(
            _binding, f"{req}", destination, relay_state=_rstate, sigalg=""
        )

        return http_args

    def get(self):
        saml_config = SAMLConfig()
        logger.info('SAML config: %s' % self._config['saml'])
        saml_config.load(self._config['saml'])
        saml_client = Saml2Client(config=saml_config)

        http_args = self._getSamlRequest(saml_client, saml_config)
        return Response(
            http_args['url'],
            http_args['status'],
        )
