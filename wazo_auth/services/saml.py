# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any, TypedDict

from saml2 import BINDING_HTTP_POST
from saml2.client import Saml2Client
from saml2.config import Config as SAMLConfig
from saml2.response import AuthnResponse, VerificationError
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding
from saml2.sigver import SignatureError

from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService
from wazo_auth.services.tenant import TenantService

logger = logging.getLogger(__name__)


@dataclass
class SamlAuthContext:
    saml_session_id: str
    redirect_url: str
    domain: str
    relay_state: str
    login: str | None = None
    response: AuthnResponse | None = None
    start_time: datetime = field(default_factory=partial(datetime.now, timezone.utc))


class SAMLACSFormData(TypedDict):
    RelayState: str
    SAMLResponse: str


RawSAMLConfig = dict[str, Any]


class WazoSAMLConfig(TypedDict):
    saml_session_lifetime_seconds: int
    key_file: str
    cert_file: str
    xmlsec_binary: str
    domains: dict[str, RawSAMLConfig]


class Config(TypedDict, total=False):
    saml: WazoSAMLConfig


RequestId = Any


class SAMLService(BaseService):
    def __init__(self, config: Config, tenant_service: TenantService):
        self._config = config
        self._outstanding_requests: dict[RequestId, SamlAuthContext] = {}
        self._saml_clients: dict[str, Saml2Client] = {}
        self._tenant_service = tenant_service

        global_saml_config = dict(self._config['saml'])
        required_config_options = [
            'key_file',
            'cert_file',
            'xmlsec_binary',
            'saml_session_lifetime_seconds',
        ]
        missing_keys = []
        for key in required_config_options:
            value = global_saml_config.get(key)
            if not value:
                missing_keys.append(key)

        if missing_keys:
            logger.error(
                'Failed to initialize SAML service, missing configuration %s',
                ','.join(missing_keys),
            )
            return

        domain_configs = global_saml_config.pop('domains', None)
        self._init_clients(global_saml_config, domain_configs)
        self._saml_session_lifetime = timedelta(
            seconds=config['saml']['saml_session_lifetime_seconds']
        )

    def _init_clients(self, global_saml_config, domain_configs):
        logger.debug('Global SAML config: %s', global_saml_config)
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

    def get_client(self, domain: str):
        return self._saml_clients[domain]

    def prepare_redirect_response(
        self,
        redirect_url: str,
        domain: str,
    ):
        saml_session_id = secrets.token_urlsafe(16)
        client = self.get_client(domain)

        relay_state: str = base64.urlsafe_b64encode(
            hashlib.sha256(saml_session_id.encode()).digest()
        ).decode()
        req_id, info = client.prepare_for_authenticate(relay_state=relay_state)

        self._outstanding_requests[req_id] = SamlAuthContext(
            saml_session_id,
            redirect_url,
            domain,
            relay_state,
        )
        location = [i for i in info['headers'] if i[0] == 'Location'][0][1]
        return location, saml_session_id

    def _decode_saml_response(
        self, saml_client: Saml2Client, saml_response: str, conv_info: dict[str, Any]
    ) -> None | AuthnResponse:
        return saml_client.parse_authn_request_response(
            saml_response,
            BINDING_HTTP_POST,
            self._outstanding_requests,
            None,
            conv_info=conv_info,
        )

    def _find_session_by_relay_state(
        self, relay_state: str
    ) -> tuple[SamlAuthContext, RequestId] | tuple[None, None]:
        sessions = [
            (reqid, context)
            for reqid, context in self._outstanding_requests.items()
            if context.relay_state == relay_state
        ]
        if len(sessions) == 1:
            reqid, context = sessions[0]
            return context, reqid
        else:
            logger.warning(
                "Unable to get SAML session corresponding to the received RelayState"
            )
            return None, None

    def _process_auth_response_error(
        self, redirect_url: str, req_id: RequestId, msg: str
    ) -> None:

        logger.warning(msg)
        logger.debug(f'Removing session: {req_id}')
        del self._outstanding_requests[req_id]
        raise exceptions.SAMLProcessingErrorWithReturnURL(
            'Unknown principal', return_url=redirect_url
        )

    def _process_auth_response_context_not_found(self) -> None:
        logger.warning('ACS response request failed: Context not found')
        raise exceptions.SAMLProcessingError('Context not found', code=404)

    def process_auth_response(
        self, url: str, remote_addr: str, form_data: SAMLACSFormData
    ) -> str:
        (
            session_by_relay_state,
            req_id_by_relay_state,
        ) = self._find_session_by_relay_state(form_data['RelayState'])
        if not session_by_relay_state:
            self._process_auth_response_context_not_found()

        domain: str = session_by_relay_state.domain
        saml_client: Saml2Client = self.get_client(domain)
        conv_info: dict[str, Any] = {
            "remote_addr": remote_addr,
            "request_uri": url,
            "entity_id": saml_client.config.entityid,
            "endpoints": saml_client.config.getattr("endpoints", "sp"),
        }

        try:
            response = self._decode_saml_response(
                saml_client, form_data['SAMLResponse'], conv_info
            )
        except UnknownPrincipal as excp:
            self._process_auth_response_error(
                session_by_relay_state.redirect_url,
                req_id_by_relay_state,
                f'UnknownPrincipal: {excp}',
            )
        except UnsupportedBinding as excp:
            self._process_auth_response_error(
                session_by_relay_state.redirect_url,
                req_id_by_relay_state,
                f'Unsupported binding: {excp}',
            )
        except VerificationError as excp:
            self._process_auth_response_error(
                session_by_relay_state.redirect_url,
                req_id_by_relay_state,
                f'Verification error: {excp}',
            )
        except SignatureError as excp:
            self._process_auth_response_error(
                session_by_relay_state.redirect_url,
                req_id_by_relay_state,
                f'Signature error: {excp}',
            )
        except Exception as excp:
            self._process_auth_response_error(
                session_by_relay_state.redirect_url,
                req_id_by_relay_state,
                f'Unexpected error: {excp}',
            )

        logger.debug('SAML SP response: %s', response)
        logger.info('SAML response AVA: %s', response.ava)

        session_data: SamlAuthContext | None = self._outstanding_requests.get(
            response.session_id()
        )

        if session_data:
            if session_data.relay_state != form_data['RelayState']:
                logger.warning(
                    'RequestId does not correspond to RelayState, ignoring response'
                )
                self._process_auth_response_context_not_found()
            update = {'response': response, 'login': response.ava['name'][0]}
            self._outstanding_requests[response.session_id()] = replace(
                session_data, **update
            )
            return session_data.redirect_url
        else:
            self._process_auth_response_context_not_found()
            return

    def get_user_login_and_remove_context(self, saml_session_id: str) -> str | None:
        logger.debug('sessions %s', self._outstanding_requests)
        reqid: str | None = self._reqid_by_saml_session_id(saml_session_id)
        if reqid:
            session_data: SamlAuthContext | None = self._outstanding_requests.pop(
                reqid, None
            )
            return session_data.login if session_data else None
        else:
            return None

    def clean_pending_requests(self, maybe_now: datetime | None = None) -> None:
        now: datetime = maybe_now or datetime.now(timezone.utc)
        for k in list(self._outstanding_requests.keys()):
            expire_at: datetime = (
                self._outstanding_requests[k].start_time + self._saml_session_lifetime
            )
            if now > expire_at:
                logger.debug(f"Removing SAML context: {self._outstanding_requests}")
                del self._outstanding_requests[k]

    def _reqid_by_saml_session_id(self, saml_session_id: str) -> str | None:
        for reqid, saml_context in self._outstanding_requests.items():
            if saml_context.saml_session_id == saml_session_id:
                return reqid
        return None
