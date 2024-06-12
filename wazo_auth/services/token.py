# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import time

from wazo_bus.resources.auth.events import (
    RefreshTokenCreatedEvent,
    RefreshTokenDeletedEvent,
    SessionCreatedEvent,
    SessionDeletedEvent,
)

from wazo_auth.services.helpers import BaseService
from wazo_auth.token import Token

from ..exceptions import (
    DuplicatedRefreshTokenException,
    MissingAccessTokenException,
    MissingTenantTokenException,
    UnknownTokenException,
)
from ..helpers import is_uuid

logger = logging.getLogger(__name__)


class TokenService(BaseService):
    def __init__(self, config, dao, tenant_tree, bus_publisher, user_service):
        super().__init__(dao, tenant_tree)
        self._deprecated_backend_policies = config.get('backend_policies', {})
        self._default_user_policy = config.get('default_user_policy')
        self._default_expiration = config['default_token_lifetime']
        self._bus_publisher = bus_publisher
        self._user_service = user_service

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

    def list_refresh_tokens(
        self, scoping_tenant_uuid=None, recurse=False, **search_params
    ):
        search_params['tenant_uuids'] = self._get_scoped_tenant_uuids(
            scoping_tenant_uuid, recurse
        )
        return self._dao.refresh_token.list_(**search_params)

    def new_token(self, backend, login, args):
        metadata = backend.get_metadata(login, args)
        logger.debug('metadata for %s: %s', login, metadata)

        auth_id = metadata['auth_id']
        pbx_user_uuid = metadata.get('pbx_user_uuid')
        xivo_uuid = metadata['xivo_uuid']
        tenant_uuid = metadata.get('tenant_uuid')

        args['acl'] = self._get_acl(args['backend'])
        args['metadata'] = metadata

        acl = backend.get_acl(login, args)
        expiration = args.get('expiration', self._default_expiration)
        current_time = time.time()

        session_payload = {}
        if tenant_uuid:
            session_payload['tenant_uuid'] = tenant_uuid
        if args.get('mobile'):
            session_payload['mobile'] = args['mobile']

        token_payload = {
            'auth_id': auth_id,
            'pbx_user_uuid': pbx_user_uuid,
            'xivo_uuid': xivo_uuid,
            'expire_t': current_time + expiration,
            'issued_t': current_time,
            'acl': acl or [],
            'metadata': metadata,
            'user_agent': args['user_agent'],
            'remote_addr': args['remote_addr'],
        }

        if args.get('access_type', 'online') == 'offline':
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
            }
            try:
                refresh_token = self._dao.refresh_token.create(body)
            except DuplicatedRefreshTokenException:
                refresh_token = self._dao.refresh_token.get_existing_refresh_token(
                    args['client_id'],
                    metadata['uuid'],
                )
            else:
                event = RefreshTokenCreatedEvent(
                    body['client_id'], body['mobile'], tenant_uuid, body['user_uuid']
                )
                self._bus_publisher.publish(event)
            token_payload['refresh_token'] = refresh_token

        token_uuid, session_uuid = self._dao.token.create(
            token_payload, session_payload
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

    def _get_tenant_list(self, tenant_uuid):
        if not tenant_uuid:
            return []

        tenant_uuids = self._tenant_tree.list_visible_tenants(tenant_uuid)
        return [{'uuid': uuid} for uuid in tenant_uuids]

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
            raise UnknownTokenException()

        id_ = token_data.pop('uuid')
        token = Token(id_, **token_data)

        if token.is_expired():
            raise UnknownTokenException()

        if not token.matches_required_access(required_access):
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

        # TODO: when the ldap_user gets remove all tokens will have a UUID
        user_uuid = token['metadata'].get('uuid')
        if not user_uuid:
            # Fallback on the token data since this is not a user token
            visible_tenants = {t['uuid'] for t in token['metadata']['tenants']}
            if tenant not in visible_tenants:
                raise MissingTenantTokenException(tenant)
            else:
                return

        if not self._user_service.user_has_subtenant(user_uuid, tenant):
            raise MissingTenantTokenException(tenant)
