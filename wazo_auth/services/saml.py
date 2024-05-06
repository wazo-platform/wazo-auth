# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Optional

from saml2 import BINDING_HTTP_POST
from saml2.client import Saml2Client
from saml2.config import Config as SAMLConfig
from saml2.response import AuthnResponse

from wazo_auth.services.helpers import BaseService

logger = logging.getLogger(__name__)


@dataclass
class SamlAuthContext:
    saml_session_id: str
    redirect_url: str
    tenant: str
    login: Optional[str] = None
    response: Optional[AuthnResponse] = None
    start_time: datetime = datetime.now(timezone.utc)


class SAMLService(BaseService):
    def __init__(self, config):
        self._config = config
        self._outstanding_requests: dict[Any, SamlAuthContext] = {}
        self._session_request_mapping: dict[str, str] = {}
        self._saml_clients: dict[str, Saml2Client] = {}

        self._init_clients()

    def _init_clients(self):
        key_file = self._config['saml']['key_file']
        cert_file = self._config['saml']['cert_file']
        if not key_file or not cert_file:
            raise Exception(
                '"key_file" or "cert_file" are missing from the SAML configuration'
            )

        global_saml_config = {
            'xmlsec_binary': self._config['saml'].get('xmlsec_binary'),
            'key_file': key_file,
            'cert_file': cert_file,
        }
        logger.debug('Global SAML config: %s', global_saml_config)
        tenant_configs = self._config['saml']['tenants']
        if not tenant_configs:
            logger.debug('No SAML configuration found for any tenant')
            return

        for tenant_identifier, raw_saml_config in tenant_configs.items():
            raw_saml_config['relay_state'] = tenant_identifier
            raw_saml_config.update(global_saml_config)
            try:
                saml_config = SAMLConfig()
                saml_config.load(raw_saml_config)
                saml_client = Saml2Client(config=saml_config)
                logger.info(
                    '####################### SAML config : %s', vars(saml_config)
                )
                self._saml_clients[tenant_identifier] = saml_client
            except Exception as inst:
                logger.error(
                    'Error during SAML client init for tenant %s', tenant_identifier
                )
                logger.exception(inst)

    def get_client(self, tenant_identifier):
        return self._saml_clients[tenant_identifier]

    def prepareRedirectResponse(
        self, samlSessionId, redirectUrl, tenantId='wazoTestTenant'
    ):
        client = self.get_client(tenantId)
        reqid, info = client.prepare_for_authenticate(relay_state=tenantId)

        self._outstanding_requests[reqid] = SamlAuthContext(
            samlSessionId, redirectUrl, tenantId
        )
        location = [i for i in info['headers'] if i[0] == 'Location'][0][1]
        return {"headers": [("Location", location)], "status": 303}

    def processAuthResponse(self, url, remote_addr, form_data):
        saml_client = self.get_client(form_data.get('RelayState'))
        conv_info = {
            "remote_addr": remote_addr,
            "request_uri": url,
            "entity_id": saml_client.config.entityid,
            "endpoints": saml_client.config.getattr("endpoints", "sp"),
        }

        response: None = saml_client.parse_authn_request_response(
            form_data['SAMLResponse'],
            BINDING_HTTP_POST,
            self._outstanding_requests,
            None,
            conv_info=conv_info,
        )

        logger.debug('SAML SP response: %s ' % response)
        logger.info('SAML response AVA: %s ' % response.ava)

        sessionData: Optional[SamlAuthContext] = self._outstanding_requests.get(
            response.session_id()
        )
        if sessionData:
            update = {'response': response, 'login': response.ava['name']}
            self._outstanding_requests[response.session_id()] = replace(
                sessionData, **update
            )
            return sessionData.redirect_url
        else:
            return None

    def getUserLogin(self, samlSessionId):
        logger.warn('sessions %s ' % self._outstanding_requests)
        for key in self._outstanding_requests:
            if self._outstanding_requests[key].saml_session_id == samlSessionId:
                reqid = key
        sessionData: Optional[SamlAuthContext] = self._outstanding_requests.get(reqid)
        logger.warn('sessionData : %s' % sessionData)
        if sessionData:
            return sessionData.login
        else:
            return None
