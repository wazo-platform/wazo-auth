# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import logging

from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    element_to_extension_element,
    xmldsig,
)
from saml2.client import Saml2Client
from saml2.config import Config as SAMLConfig
from saml2.extension.pefim import SPCertEnc
from saml2.s_utils import rndstr
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.samlp import Extensions

from wazo_auth.services.helpers import BaseService

logger = logging.getLogger(__name__)


class SAMLService(BaseService):
    def __init__(self, config):
        self._config = config
        if 'saml' in self._config:
            try:
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
                logger.info(
                    '####################### SAML config : %s' % vars(self._saml_config)
                )
            except Exception as inst:
                logger.error('Error during SAML client init')
                logger.exception(inst)
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

    def initFlow(self):
        idps = self._saml_client.metadata.identity_providers()

        entity_id = idps[0]

        _binding, destination = self._saml_client.pick_binding(
            "single_sign_on_service",
            [BINDING_HTTP_REDIRECT],
            "idpsso",
            entity_id=entity_id,
        )
        logger.debug("binding: %s, destination: %s", _binding, destination)
        acs = self._saml_client.config.getattr("endpoints", "sp")[
            "assertion_consumer_service"
        ]
        _, return_binding = acs[0]

        extensions = None
        if self._saml_client.config.generate_cert_func is not None:
            cert_str, req_key_str = self._saml_client.config.generate_cert_func()
            spcertenc = SPCertEnc(
                x509_data=xmldsig.X509Data(
                    x509_certificate=xmldsig.X509Certificate(text=cert_str)
                )
            )
            extensions = Extensions(
                extension_elements=[element_to_extension_element(spcertenc)]
            )

        req_id, req = self._saml_client.create_authn_request(
            destination,
            binding=return_binding,
            extensions=extensions,
            nameid_format=NAMEID_FORMAT_PERSISTENT,
        )
        _rstate = rndstr()
        http_args = self._saml_client.apply_binding(
            _binding, f"{req}", destination, relay_state=_rstate, sigalg=""
        )
        return http_args

    def processAuthResponse(self, url, remote_addr, form_data):
        conv_info = {
            "remote_addr": remote_addr,
            "request_uri": url,
            "entity_id": self._saml_client.config.entityid,
            "endpoints": self._saml_client.config.getattr("endpoints", "sp"),
        }

        response = self._saml_client.parse_authn_request_response(
            form_data,
            BINDING_HTTP_POST,
            None,
            None,
            conv_info=conv_info,
        )

        logger.debug('SAML SP response: %s ' % response)
        return response
