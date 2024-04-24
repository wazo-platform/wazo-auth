# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


import ast
import logging

from flask import redirect, request
from saml2.client import Saml2Client
from saml2.config import Config as SAMLConfig

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
        if 'saml' in self._config:
            self._saml_config = SAMLConfig()
            if isinstance(
                self._config['saml']['service']['sp']['endpoints'][
                    'assertion_consumer_service'
                ][0],
                str,
            ):
                self._saml_config.load(self._updateConfig(self._config['saml']))
            else:
                self._saml_config.load(self._config['saml'])
            self._saml_client = Saml2Client(config=self._saml_config)
        else:
            logger.warn(
                'SAML config is missing, won\'t be able to provide SAML related services'
            )

    def _extractTuplesFromListOfStrings(self, ls):
        e = [tuple(i.removeprefix('(').removesuffix(')').split(',')) for i in ls]
        return [
            (ast.literal_eval(i[0].strip()), ast.literal_eval(i[1].strip())) for i in e
        ]

    def _updateConfig(self, config):
        acs = self._extractTuplesFromListOfStrings(
            config['service']['sp']['endpoints']['assertion_consumer_service']
        )
        slo = self._extractTuplesFromListOfStrings(
            config['service']['sp']['endpoints']['single_logout_service']
        )
        u_config = {'assertion_consumer_service': acs, 'single_logout_service': slo}
        config['service']['sp']['endpoints'].update(u_config)
        return config

    def _getSamlRequest(self, saml_client, saml_config):
        idps = saml_client.metadata.identity_providers()

        entity_id = idps[0]

        _binding, destination = saml_client.pick_binding(
            "single_sign_on_service",
            [BINDING_HTTP_REDIRECT],
            "idpsso",
            entity_id=entity_id,
        )
        logger.debug("binding: %s, destination: %s", _binding, destination)
        acs = saml_client.config.getattr("endpoints", "sp")[
            "assertion_consumer_service"
        ]
        _, return_binding = acs[0]

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
        if hasattr(self, '_saml_client'):
            http_args = self._getSamlRequest(self._saml_client, self._saml_config)
            return Response(headers=http_args['headers'], status=http_args['status'])
        else:
            return Response(
                status=500,
                response='SAML configuration missing or SAML client init failed',
            )
