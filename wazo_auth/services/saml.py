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
from typing import TYPE_CHECKING, Any, NamedTuple, NoReturn, TypedDict
from urllib.parse import unquote
from uuid import UUID

from saml2 import BINDING_HTTP_POST
from saml2.client import Saml2Client
from saml2.config import Config as SAMLConfig
from saml2.response import AuthnResponse, VerificationError
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding
from saml2.saml import name_id_from_string
from saml2.sigver import SignatureError

if TYPE_CHECKING:
    from wazo_auth.database.queries import DAO

from wazo_auth import exceptions
from wazo_auth.exceptions import (
    SAMLConfigurationError,
    SAMLProcessingError,
    SAMLProcessingErrorWithReturnURL,
)
from wazo_auth.services.helpers import BaseService
from wazo_auth.services.tenant import TenantService

logger = logging.getLogger(__name__)


@dataclass
class SamlAuthContext(dict):
    saml_session_id: str
    redirect_url: str
    domain: str
    relay_state: str
    login: str | None = None
    start_time: datetime = field(default_factory=partial(datetime.now, timezone.utc))
    saml_name_id: str | None = None
    refresh_token_uuid: UUID | None = None


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
        self._saml_login_timeout = timedelta(
            seconds=config['saml']['saml_login_timeout_seconds']
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
                    # avoid circular import issue
                    from wazo_auth.database.queries.saml_pysaml2_cache import (
                        SAMLPysaml2CacheDAO,
                    )

                    saml_config = SAMLConfig()
                    saml_config.load(cnf=raw_saml_config)
                    saml_client = Saml2Client(
                        config=saml_config, identity_cache=SAMLPysaml2CacheDAO()
                    )
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
        sessions: list[SamlSessionItem] = self._dao.saml_session.list(
            relay_state=relay_state
        )
        if sessions:
            return sessions[0]
        else:
            logger.warning(
                "Unable to get SAML session corresponding to the received RelayState"
            )
            return None, None

    def _process_auth_response_error(
        self, redirect_url: str, req_id: RequestId, msg: str
    ) -> NoReturn:

        logger.warning(msg)
        logger.debug('Removing session: %s', req_id)
        self._dao.saml_session.delete(req_id)
        raise SAMLProcessingErrorWithReturnURL(
            'Unknown principal', return_url=redirect_url
        )

    def process_auth_response(
        self, url: str, remote_addr: str, form_data: SAMLACSFormData
    ) -> str | NoReturn:
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

                update: dict[str, Any] = {
                    'login': response.ava['name'][0],
                    'saml_name_id': str(response.name_id),
                }
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
            logger.exception(excp)
            self._process_auth_response_error(
                saml_session.auth_context.redirect_url,
                saml_session.request_id,
                f'Unexpected error: {excp}',
            )

    def get_user_login(self, saml_session_id: str) -> str | None:
        logger.debug('sessions %s', self._dao.saml_session.list())
        for reqid, session_data in self._dao.saml_session.list(
            session_id=saml_session_id
        ):
            try:
                return session_data.login
            except AttributeError:
                logger.warning(
                    'User login not found for saml_session_id %s', saml_session_id
                )
                return None

    def invalidate_saml_session_id(self, saml_session_id: str) -> str | None:
        logger.debug('sessions %s', self._dao.saml_session.list())
        for reqid, session in self._dao.saml_session.list(session_id=saml_session_id):
            update: dict[str, None] = {'session_id': 'token-already-used'}
            self._dao.saml_session.update(reqid, **update)
            return
        raise exceptions.SAMLProcessingError(
            'Unable to remove unexisting SAML Session ID'
        )

    def update_refresh_token(self, refresh_token: UUID, saml_session_id: str) -> None:
        for session_data in self._dao.saml_session.list(session_id=saml_session_id):
            update = {'refresh_token_uuid': refresh_token}
            self._dao.saml_session.update(session_data.request_id, **update)

    def _clean_saml_sessions(self, now: datetime) -> None:
        for item in self._dao.saml_session.list():
            context: SamlAuthContext = item.auth_context
            expire_at: datetime = context.start_time + self._saml_session_lifetime
            if (
                now > expire_at
                and context.saml_session_id == 'token_already_used'
                and context.refresh_token_uuid is None
            ):
                logger.debug('Deleting used SAML session: %s', item)
                self._dao.saml_session.delete(item.request_id)
            elif now > expire_at and context.saml_session_id != 'token_already_used':
                logger.debug("Deleting SAML session on timeout: %s", item)
                self._dao.saml_session.delete(item.request_id)

    def _clean_pysaml2_sessions(self, now: datetime) -> None:
        session_expired: datetime = (
            datetime.now(tz=timezone.utc) - self._saml_session_lifetime
        )
        session_expired_timestamp: int = int(round(session_expired.timestamp()))
        for item in self._dao.saml_pysaml2_cache.get_expired(session_expired_timestamp):
            logger.debug("Deleting from pysaml2 cache: %s", item.name_id)
            self._dao.saml_pysaml2_cache.delete_encoded(item.name_id)

    def clean_pending_requests(self, maybe_now: datetime | None = None) -> None:
        now: datetime = maybe_now or datetime.now(timezone.utc)
        self._clean_saml_sessions(now)
        self._clean_pysaml2_sessions(now)

    def process_logout_request(self, token):
        logger.debug(
            'Processing logout for token: ...%s',
            "".join(
                [
                    'xxxxxx...',
                    (token.refresh_token_uuid or token.token or 'unknown token')[-8:],
                ]
            ),
        )
        session: list[SamlSessionItem] = [
            item
            for item in self._dao.saml_session.list()
            if item.auth_context.refresh_token_uuid == token.refresh_token_uuid
            and item.auth_context.login is not None
        ]

        if not session:
            logger.warning('Logout request failed: Context not found')
            raise SAMLProcessingError('Context not found', code=404)

        client = self.get_client(session[0].auth_context.domain)
        name_id = name_id_from_string(session[0].auth_context.saml_name_id)

        data = client.global_logout(name_id)
        try:
            _, details = data.popitem()
        except KeyError:
            logger.info('SAML logout failed, error or already logged out')
            self._dao.saml_session.delete(session[0].request_id)
            return session[0].auth_context.redirect_url + '?logged_out=true'

        location = details[1]['headers'][0][1]

        relay_state = unquote(location.split('RelayState=')[1]).split('&')[0]
        update = {'relay_state': relay_state}

        self._dao.saml_session.update(session[0].request_id, **update)
        return location

    def process_logout_request_response(self, message, relay_state, binding):
        saml_session = self._find_session_by_relay_state(relay_state)
        client = self.get_client(saml_session.auth_context.domain)
        response = client.parse_logout_request_response(message, binding)
        client.handle_logout_response(response)

        self._dao.saml_session.delete(saml_session.request_id)

        return saml_session.auth_context.redirect_url + '?logged_out=true'
