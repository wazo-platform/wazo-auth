# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import TYPE_CHECKING, Any, NamedTuple, TypedDict

from saml2 import BINDING_HTTP_POST
from saml2.client import Saml2Client
from saml2.config import Config as SAMLConfig
from saml2.response import AuthnResponse, VerificationError
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding
from saml2.sigver import SignatureError

if TYPE_CHECKING:
    from wazo_auth.database.queries import DAO

from wazo_auth.exceptions import (
    SAMLConfigurationError,
    SAMLProcessingError,
    SAMLProcessingErrorWithReturnURL,
)
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


RequestId = str


class SamlSessionItem(NamedTuple):
    request_id: RequestId
    auth_context: SamlAuthContext


class SAMLService(BaseService):
    def __init__(self, config: Config, tenant_service: TenantService, dao: DAO):
        self._config: Config = config
        self._saml_clients: dict[str, Saml2Client] = {}
        self._tenant_service: TenantService = tenant_service
        self._dao: DAO = dao

        self._key_file = self._config['saml']['key_file']
        self._cert_file = self._config['saml']['cert_file']

        self._global_saml_config = dict(self._config['saml'])
        required_config_options = [
            'key_file',
            'cert_file',
            'xmlsec_binary',
            'saml_session_lifetime_seconds',
        ]
        missing_keys = []
        for key in required_config_options:
            value = self._global_saml_config.get(key)
            if not value:
                missing_keys.append(key)

        if missing_keys:
            logger.error(
                'Failed to initialize SAML service, missing configuration %s',
                ','.join(missing_keys),
            )
            return
        logger.debug('Global SAML config: %s', self._global_saml_config)
        self._saml_session_lifetime = timedelta(
            seconds=config['saml']['saml_session_lifetime_seconds']
        )

    def _prepare_saml_config(self, db_config, filename, globals) -> RawSAMLConfig:
        return {
            'entityid': db_config['entity_id'],
            'service': {
                'sp': {
                    'want_response_signed': True,
                    'authn_requests_signed': True,
                    'endpoints': {
                        'assertion_consumer_service': [
                            (
                                db_config['acs_url'],
                                BINDING_HTTP_POST,
                            )
                        ]
                    },
                }
            },
            'metadata': {'local': [filename]},
            'key_file': globals['key_file'],
            'cert_file': globals['cert_file'],
            'xmlsec_binary': globals['xmlsec_binary'],
        }

    def init_clients(self, db_configs):
        self._saml_clients = {}
        key_file = self._config['saml']['key_file']
        cert_file = self._config['saml']['cert_file']
        if not key_file or not cert_file:
            raise SAMLConfigurationError(
                db_configs['domain_name'],
                '"key_file" or "cert_file" are missing from the SAML configuration',
            )

        logger.info("(re)Initializing SAML clients with config: %s", db_configs)
        if not db_configs:
            logger.debug('No SAML configuration found for any domain')
            return

        for db_config in db_configs:
            domain_name = db_config['domain_name']
            matching_tenants = self._tenant_service.list_(
                domain_name=domain_name, scoping_tenant_uuid=None
            )
            if not matching_tenants:
                logger.info(
                    'Ignoring SAML config for "%s" no matching tenant', domain_name
                )
                continue

            with tempfile.NamedTemporaryFile(suffix='.xml') as metadata_file:
                metadata_file.write(db_config['idp_metadata'].encode())
                metadata_file.flush()
                raw_saml_config = self._prepare_saml_config(
                    db_config, metadata_file.name, self._global_saml_config
                )
                raw_saml_config['relay_state'] = domain_name
                logger.debug(
                    'SAML config for domain: %s: %s', domain_name, raw_saml_config
                )
                try:
                    saml_config = SAMLConfig()
                    saml_config.load(cnf=raw_saml_config)
                    saml_client = Saml2Client(config=saml_config)
                    logger.debug(
                        'SAML config for domain: %s: %s', domain_name, vars(saml_config)
                    )
                    self._saml_clients[domain_name] = saml_client
                except Exception:
                    logger.exception(
                        'Error during SAML client init for domain %s', domain_name
                    )

    def get_client(self, domain: str):
        return self._saml_clients[domain]

    def prepare_redirect_response(
        self,
        redirect_url: str,
        domain: str,
    ):
        saml_session_id = secrets.token_urlsafe(16)
        client: Saml2Client = self.get_client(domain)

        relay_state: str = base64.urlsafe_b64encode(
            hashlib.sha256(saml_session_id.encode()).digest()
        ).decode()
        req_id, info = client.prepare_for_authenticate(relay_state=relay_state)

        self._dao.saml_session.create(
            SamlSessionItem(
                req_id,
                SamlAuthContext(
                    saml_session_id,
                    redirect_url,
                    domain,
                    relay_state,
                ),
            )
        )
        location = [i for i in info['headers'] if i[0] == 'Location'][0][1]
        return location, saml_session_id

    def _decode_saml_response(
        self, saml_client: Saml2Client, saml_response: str, conv_info: dict[str, Any]
    ) -> None | AuthnResponse:
        return saml_client.parse_authn_request_response(
            saml_response,
            BINDING_HTTP_POST,
            {
                item.request_id: item.auth_context
                for item in self._dao.saml_session.list()
            },
            None,
            conv_info=conv_info,
        )

    def _find_session_by_relay_state(
        self, relay_state: str
    ) -> SamlSessionItem | tuple[None, None]:
        sessions: list[SamlSessionItem] = [
            item
            for item in self._dao.saml_session.list()
            if item.auth_context.relay_state == relay_state
        ]
        if sessions:
            return sessions[0]
        else:
            logger.warning(
                "Unable to get SAML session corresponding to the received RelayState"
            )
            return None, None

    def _process_auth_response_error(
        self, redirect_url: str, req_id: RequestId, msg: str
    ) -> None:

        logger.warning(msg)
        logger.debug('Removing session: %s', req_id)
        self._dao.saml_session.delete(req_id)
        raise SAMLProcessingErrorWithReturnURL(
            'Unknown principal', return_url=redirect_url
        )

    def process_auth_response(
        self, url: str, remote_addr: str, form_data: SAMLACSFormData
    ) -> str:
        saml_session: SamlSessionItem | tuple[
            None, None
        ] = self._find_session_by_relay_state(form_data['RelayState'])
        if saml_session == (None, None):
            logger.warning('ACS response request failed: Context not found')
            raise SAMLProcessingError('Context not found', code=404)

        domain: str = saml_session.auth_context.domain
        saml_client: Saml2Client = self.get_client(domain)
        conv_info: dict[str, Any] = {
            "remote_addr": remote_addr,
            "request_uri": url,
            "entity_id": saml_client.config.entityid,
            "endpoints": saml_client.config.getattr("endpoints", "sp"),
        }

        try:
            response: AuthnResponse | None = self._decode_saml_response(
                saml_client, form_data['SAMLResponse'], conv_info
            )
            if response is None:
                self._process_auth_response_error(
                    saml_session.auth_context.redirect_url,
                    saml_session.request_id,
                    'Unexpected error: parsed response is empty',
                )

            logger.debug('SAML SP response: %s', response)
            logger.info('SAML response AVA: %s', response.ava)

            session_data: SamlAuthContext | None = self._dao.saml_session.get(
                response.session_id()
            )

            if session_data:
                if session_data.auth_context.relay_state != form_data['RelayState']:
                    logger.warning(
                        'RequestId does not correspond to RelayState, ignoring response'
                    )
                    logger.warning('ACS response request failed: Context not found')
                    raise SAMLProcessingError('Context not found', code=404)

                update = {'login': response.ava['name'][0]}
                self._dao.saml_session.update(response.session_id(), **update)
                return session_data.auth_context.redirect_url
            else:
                logger.warning('ACS response request failed: Context not found')
                raise SAMLProcessingError('Context not found', code=404)

        except UnknownPrincipal as excp:
            self._process_auth_response_error(
                saml_session.auth_context.redirect_url,
                saml_session.request_id,
                f'UnknownPrincipal: {excp}',
            )
        except UnsupportedBinding as excp:
            self._process_auth_response_error(
                saml_session.auth_context.redirect_url,
                saml_session.request_id,
                f'Unsupported binding: {excp}',
            )
        except VerificationError as excp:
            self._process_auth_response_error(
                saml_session.auth_context.redirect_url,
                saml_session.request_id,
                f'Verification error: {excp}',
            )
        except SignatureError as excp:
            self._process_auth_response_error(
                saml_session.auth_context.redirect_url,
                saml_session.request_id,
                f'Signature error: {excp}',
            )
        except Exception as excp:
            self._process_auth_response_error(
                saml_session.auth_context.redirect_url,
                saml_session.request_id,
                f'Unexpected error: {excp}',
            )

    def get_user_login_and_remove_context(self, saml_session_id: str) -> str | None:
        logger.debug('sessions %s', self._dao.saml_session.list())
        reqid: str | None = self._reqid_by_saml_session_id(saml_session_id)
        if reqid:
            _, session_data = self._dao.saml_session.get(reqid)
            self._dao.saml_session.delete(reqid)
            return session_data.login if session_data else None
        else:
            return None

    def clean_pending_requests(self, maybe_now: datetime | None = None) -> None:
        now: datetime = maybe_now or datetime.now(timezone.utc)
        for item in self._dao.saml_session.list():
            expire_at: datetime = (
                item.auth_context.start_time + self._saml_session_lifetime
            )
            if now > expire_at:
                logger.debug("Removing SAML context: %s", item)
                self._dao.saml_session.delete(item.request_id)

    def _reqid_by_saml_session_id(self, saml_session_id: str) -> str | None:
        for reqid, saml_context in self._dao.saml_session.list():
            if saml_context.saml_session_id == saml_session_id:
                return reqid
        return None
