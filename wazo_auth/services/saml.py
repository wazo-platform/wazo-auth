# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import secrets
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
    domain: str
    login: Optional[str] = None
    response: Optional[AuthnResponse] = None
    start_time: datetime = datetime.now(timezone.utc)


class SAMLService(BaseService):
    def __init__(self, config, tenant_service):
        self._config = config
        self._outstanding_requests: dict[Any, SamlAuthContext] = {}
        self._session_request_mapping: dict[str, str] = {}
        self._saml_clients: dict[str, Saml2Client] = {}
        self._tenant_service = tenant_service

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
        domain_configs = self._config['saml']['domains']
        if not domain_configs:
            logger.debug('No SAML configuration found for any domain')
            return

        for domain, raw_saml_config in domain_configs.items():
            matching_tenants = self._tenant_service.list_(
                domain_name=domain, scoping_tenant_uuid=None
            )
            if not matching_tenants:
                logger.info('Ignoring SAML config for "%s" no matching tenant', domain)
                continue
            raw_saml_config['relay_state'] = domain
            raw_saml_config.update(global_saml_config)
            try:
                saml_config = SAMLConfig()
                saml_config.load(raw_saml_config)
                saml_client = Saml2Client(config=saml_config)
                logger.debug('SAML config : %s', vars(saml_config))
                self._saml_clients[domain] = saml_client
            except Exception:
                logger.exception('Error during SAML client init for domain %s', domain)

    def get_client(self, domain):
        return self._saml_clients[domain]

    def prepare_redirect_response(
        self,
        redirect_url,
        domain,
    ):
        saml_session_id = secrets.token_urlsafe(16)
        client = self.get_client(domain)
        reqid, info = client.prepare_for_authenticate(relay_state=domain)

        self._outstanding_requests[reqid] = SamlAuthContext(
            saml_session_id,
            redirect_url,
            domain,
        )
        location = [i for i in info['headers'] if i[0] == 'Location'][0][1]
        return location, saml_session_id

    def process_auth_response(self, url, remote_addr, form_data):
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

        logger.debug('SAML SP response: %s', response)
        logger.info('SAML response AVA: %s', response.ava)

        session_data: Optional[SamlAuthContext] = self._outstanding_requests.get(
            response.session_id()
        )
        if session_data:
            update = {'response': response, 'login': response.ava['name']}
            self._outstanding_requests[response.session_id()] = replace(
                session_data, **update
            )
            return session_data.redirect_url
        else:
            return None

    def get_user_login(self, saml_session_id):
        logger.debug('sessions %s', self._outstanding_requests)
        for key in self._outstanding_requests:
            if self._outstanding_requests[key].saml_session_id == saml_session_id:
                reqid = key
        session_data: Optional[SamlAuthContext] = self._outstanding_requests.get(reqid)
        logger.debug('session_data : %s', session_data)
        if session_data:
            return session_data.login
        else:
            return None
