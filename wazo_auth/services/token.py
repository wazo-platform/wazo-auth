# Copyright 2018-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import time

from wazo_bus.resources.auth.events import (
    RefreshTokenCreatedEvent,
    RefreshTokenDeletedEvent,
    SessionCreatedEvent,
    SessionDeletedEvent,
)

from wazo_auth.interfaces import BaseAuthenticationBackend
from wazo_auth.services.helpers import BaseService
from wazo_auth.token import Token

from ..exceptions import (
    DuplicatedRefreshTokenException,
    MaxConcurrentSessionsReached,
    MissingAccessTokenException,
    MissingTenantTokenException,
    UnknownTokenException,
)
from ..helpers import is_uuid

logger = logging.getLogger(__name__)


class TokenService(BaseService):
    def __init__(self, config, dao, bus_publisher, user_service):
        super().__init__(dao)
        self._deprecated_backend_policies = config.get('backend_policies', {})
        self._default_user_policy = config.get('default_user_policy')
        self._default_expiration = config['default_token_lifetime']
        self._bus_publisher = bus_publisher
        self._user_service = user_service
        self._max_user_sessions = config['max_user_concurrent_sessions']

    def count_refresh_tokens(
        self, scoping_tenant_uuid=None, recurse=False, **search_params
    ):
        search_params['tenant_uuids'] = self._get_scoped_tenant_uuids(
            scoping_tenant_uuid, recurse
        )
        return self._dao.refresh_token.count(**search_params)

    def delete_refresh_token(self, scoping_tenant_uuid, user_uuid, client_id):
        tenant_uuids = self._get_scoped_tenant_uuids(scoping_tenant_uuid, True)
        refresh_token = self._dao.refresh_token.get_by_user(
            tenant_uuids=tenant_uuids,
            user_uuid=user_uuid,
            client_id=client_id,
        )

        event = RefreshTokenDeletedEvent(
            client_id, refresh_token['mobile'], refresh_token['tenant_uuid'], user_uuid
        )
        self._bus_publisher.publish(event)
        self._dao.refresh_token.delete(tenant_uuids, user_uuid, client_id)

    def delete_refresh_token_by_uuid(self, uuid):
        refresh_token = self._dao.refresh_token.get_by_uuid(uuid)
        event = RefreshTokenDeletedEvent(
            refresh_token['client_id'],
            refresh_token['mobile'],
            refresh_token['tenant_uuid'],
            refresh_token['user_uuid'],
        )
        self._bus_publisher.publish(event)
        self._dao.refresh_token.delete(
            refresh_token['tenant_uuid'],
            refresh_token['user_uuid'],
            refresh_token['client_id'],
        )

    def list_refresh_tokens(
        self, scoping_tenant_uuid=None, recurse=False, **search_params
    ):
        search_params['tenant_uuids'] = self._get_scoped_tenant_uuids(
            scoping_tenant_uuid, recurse
        )
        return self._dao.refresh_token.list_(**search_params)

    def new_token(self, backend: BaseAuthenticationBackend, login, args):
        metadata = backend.get_metadata(login, args)
        logger.debug('fresh token metadata for %s: %s', login, metadata)

        auth_id = metadata['auth_id']
        pbx_user_uuid = metadata.get('pbx_user_uuid')
        xivo_uuid = metadata['xivo_uuid']
        tenant_uuid = metadata.get('tenant_uuid')
        purpose = metadata.get('purpose')

        if is_uuid(auth_id) and purpose in ('user', 'external_api'):
            sessions = self._dao.session.count(user_uuid=auth_id)
            if sessions >= self._max_user_sessions:
                raise MaxConcurrentSessionsReached(auth_id)

        args['acl'] = self._get_acl(args['backend'])

        acl = backend.get_acl(login, args)
        expiration = args.get('expiration', self._default_expiration)
        current_time = time.time()

        session_payload = {}
        if tenant_uuid:
            session_payload['tenant_uuid'] = tenant_uuid
        if args.get('mobile'):
            session_payload['mobile'] = args['mobile']

        # refresh token expected to expose its metadata during refresh token login
        persistent_metadata = args.get('persistent_metadata', {})
        logger.debug('persistent metadata for %s: %s', login, persistent_metadata)

        token_payload = {
            'auth_id': auth_id,
            'pbx_user_uuid': pbx_user_uuid,
            'xivo_uuid': xivo_uuid,
            'expire_t': current_time + expiration,
            'issued_t': current_time,
            'acl': acl or [],
            'metadata': persistent_metadata | metadata,
            'user_agent': args['user_agent'],
            'remote_addr': args['remote_addr'],
        }

        if args.get('access_type', 'online') == 'offline':
            persistent_metadata = backend.get_persistent_metadata(login, args)
            logger.debug(
                'freshly generated persistent metadata for %s: %s',
                login,
                persistent_metadata,
            )

            body = {
                'backend': args['backend'],
                'login': args['login']
                if not args.get('real_login')
                else args['real_login'],
                'client_id': args['client_id'],
                'user_uuid': metadata['uuid'],
                'user_agent': args['user_agent'],
                'remote_addr': args['remote_addr'],
                'mobile': args['mobile'],
                'metadata': persistent_metadata,
            }
            try:
                refresh_token = self._dao.refresh_token.create(body)
            except DuplicatedRefreshTokenException:
                refresh_token = self._dao.refresh_token.get_existing_refresh_token(
                    args['client_id'],
                    metadata['uuid'],
                )
            else:
                # TODO: add persistent metadata to event?
                event = RefreshTokenCreatedEvent(
                    body['client_id'], body['mobile'], tenant_uuid, body['user_uuid']
                )
                self._bus_publisher.publish(event)
            token_payload['refresh_token'] = refresh_token
            token_payload['metadata'] = persistent_metadata | token_payload['metadata']

        token_uuid, session_uuid = self._dao.token.create(
            token_payload,
            session_payload,
            args.get('refresh_token', None) or token_payload.get('refresh_token', None),
        )
        token = Token(token_uuid, session_uuid=session_uuid, **token_payload)

        user_uuid = auth_id if is_uuid(auth_id) else None
        event = SessionCreatedEvent(
            session_uuid,
            session_payload.get('mobile', False),
            session_payload['tenant_uuid'],
            user_uuid,
        )
        self._bus_publisher.publish(event)

        return token

    def new_token_internal(self, expiration=None, acl=None):
        expiration = expiration if expiration is not None else self._default_expiration
        acl = acl or []
        current_time = time.time()
        token_args = {
            'auth_id': 'wazo-auth',
            'pbx_user_uuid': None,
            'xivo_uuid': None,
            'expire_t': current_time + expiration,
            'issued_t': current_time,
            'acl': acl,
            'metadata': {'tenant_uuid': self.top_tenant_uuid},
            'user_agent': 'wazo-auth-internal',
            'remote_addr': '127.0.0.1',
        }
        session_args = {}
        token_uuid, session_uuid = self._dao.token.create(token_args, session_args)
        token = Token(token_uuid, session_uuid=session_uuid, **token_args)
        return token

    def remove_token(self, token_uuid):
        token, session = self._dao.token.delete(token_uuid)
        if not session:
            return

        event = SessionDeletedEvent(
            session['uuid'], session['tenant_uuid'], token['auth_id']
        )
        self._bus_publisher.publish(event)

    def get(self, token_uuid, required_access):
        token_data = self._dao.token.get(token_uuid)
        if not token_data:
            logger.debug('Rejecting unknown token')
            raise UnknownTokenException()

        id_ = token_data.pop('uuid')
        token = Token(id_, **token_data)

        if token.is_expired():
            logger.debug('Rejecting token: expired')
            raise UnknownTokenException()

        if not token.matches_required_access(required_access):
            logger.debug('Rejecting token: forbidden access')
            raise MissingAccessTokenException(required_access)

        return token

    def check_scopes(self, token_uuid, scopes):
        token_data = self._dao.token.get(token_uuid)
        if not token_data:
            raise UnknownTokenException()

        id_ = token_data.pop('uuid')
        token = Token(id_, **token_data)

        if token.is_expired():
            raise UnknownTokenException()

        scope_statuses = {
            scope: token.matches_required_access(scope) for scope in set(scopes)
        }

        return token, scope_statuses

    def _get_acl(self, backend_name):
        # 21.14: deprecated
        policy_name = self._deprecated_backend_policies.get(backend_name)

        if not policy_name:
            policy_name = self._default_user_policy

        if not policy_name:
            return []

        policy = self._dao.policy.find_by(name=policy_name)
        if not policy:
            logger.info(
                'Unknown policy name "%s" configured for backend "%s"',
                policy_name,
                backend_name,
            )
            return []
        return policy.acl

    def assert_has_tenant_permission(self, token, tenant):
        if not tenant:
            return

        # internal token emitted by wazo-auth
        if token['auth_id'] == 'wazo-auth':
            return

        user_uuid = token['auth_id']
        if not self._user_service.user_has_subtenant(user_uuid, tenant):
            logger.debug('Rejecting token: forbidden tenant')
            raise MissingTenantTokenException(tenant)

    def get_refresh_token_info(self, refresh_token: str, client_id: str) -> dict:
        refresh_token_data = self._dao.refresh_token.get(
            refresh_token,
            client_id,
        )
        return refresh_token_data
