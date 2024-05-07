# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import ast
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

    def prepareRedirectResponse(
        self, samlSessionId, redirectUrl, tenantId='wazoTestTenant'
    ):
        reqid, info = self._saml_client.prepare_for_authenticate(relay_state=tenantId)

        self._outstanding_requests[reqid] = SamlAuthContext(
            samlSessionId, redirectUrl, tenantId
        )
        location = [i for i in info['headers'] if i[0] == 'Location'][0][1]
        return {"headers": [("Location", location)], "status": 303}

    def processAuthResponse(self, url, remote_addr, form_data):
        conv_info = {
            "remote_addr": remote_addr,
            "request_uri": url,
            "entity_id": self._saml_client.config.entityid,
            "endpoints": self._saml_client.config.getattr("endpoints", "sp"),
        }

        response: None | AuthnResponse = self._saml_client.parse_authn_request_response(
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
