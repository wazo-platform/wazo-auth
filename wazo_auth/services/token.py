# Copyright 2018-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time
import logging

from xivo_bus.resources.auth.events import (
    RefreshTokenCreatedEvent,
    RefreshTokenDeletedEvent,
    SessionCreatedEvent,
    SessionDeletedEvent,
)

from wazo_auth.token import Token
from wazo_auth.services.helpers import BaseService

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
        self._backend_policies = config.get('backend_policies', {})
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
            client_id=client_id,
            user_uuid=user_uuid,
            tenant_uuid=refresh_token['tenant_uuid'],
            mobile=refresh_token['mobile'],
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

        args['acl'] = self._get_acl(args['backend'])
        args['metadata'] = metadata

        acl = backend.get_acl(login, args)
        expiration = args.get('expiration', self._default_expiration)
        current_time = time.time()

        session_payload = {}
        if metadata.get('tenant_uuid'):
            session_payload['tenant_uuid'] = metadata['tenant_uuid']
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
                'login': args['login'],
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
                    tenant_uuid=metadata.get('tenant_uuid'), **body
                )
                self._bus_publisher.publish(event)
            token_payload['refresh_token'] = refresh_token

        token_uuid, session_uuid = self._dao.token.create(
            token_payload, session_payload
        )
        token = Token(token_uuid, session_uuid=session_uuid, **token_payload)

        user_uuid = auth_id if is_uuid(auth_id) else None
        event = SessionCreatedEvent(
            session_uuid, user_uuid=user_uuid, **session_payload
        )
        self._bus_publisher.publish(event)

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
            uuid=session['uuid'],
            user_uuid=token['auth_id'],
            tenant_uuid=session['tenant_uuid'],
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
        policy_name = self._backend_policies.get(backend_name)
        if not policy_name:
            return []

        matching_policies = self._dao.policy.list_(name=policy_name, limit=1)
        for policy in matching_policies:
            return policy.acl

        logger.info(
            'Unknown policy name "%s" configured for backend "%s"',
            policy_name,
            backend_name,
        )
        return []

    def assert_has_tenant_permission(self, token, tenant):
        if not tenant:
            return

        # TODO: when the ldap_user gets remove all tokens will have a UUID
        user_uuid = token['metadata'].get('uuid')
        if not user_uuid:
            # Fallback on the token data since this is not a user token
            visible_tenants = set(t['uuid'] for t in token['metadata']['tenants'])
            if tenant not in visible_tenants:
                raise MissingTenantTokenException(tenant)
            else:
                return

        if not self._user_service.user_has_sub_tenant(user_uuid, tenant):
            raise MissingTenantTokenException(tenant)
