# Copyright 2018-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time
import logging

from xivo_bus.resources.auth.events import (
    SessionCreatedEvent,
    SessionDeletedEvent,
)

from wazo_auth.token import Token
from ..exceptions import (
    MissingACLTokenException,
    UnknownTokenException,
)

logger = logging.getLogger(__name__)


class TokenService:

    def __init__(self, config, dao, tenant_tree, bus_publisher):
        self._backend_policies = config.get('backend_policies', {})
        self._default_expiration = config['default_token_lifetime']
        self._dao = dao
        self._tenant_tree = tenant_tree
        self._bus_publisher = bus_publisher

    def new_token(self, backend, login, args):
        metadata = backend.get_metadata(login, args)
        logger.debug('metadata for %s: %s', login, metadata)

        auth_id = metadata['auth_id']
        user_uuid = metadata.get('xivo_user_uuid')
        xivo_uuid = metadata['xivo_uuid']

        args['acl_templates'] = self._get_acl_templates(args['backend'])
        args['metadata'] = metadata

        acls = backend.get_acls(login, args)
        expiration = args.get('expiration', self._default_expiration)
        current_time = time.time()

        session_payload = {}
        if metadata.get('tenant_uuid'):
            session_payload['tenant_uuid'] = metadata['tenant_uuid']
        if args.get('mobile'):
            session_payload['mobile'] = args['mobile']

        token_payload = {
            'auth_id': auth_id,
            'xivo_user_uuid': user_uuid,
            'xivo_uuid': xivo_uuid,
            'expire_t': current_time + expiration,
            'issued_t': current_time,
            'acls': acls or [],
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
            }
            refresh_token = self._dao.refresh_token.create(body)
            token_payload['refresh_token'] = refresh_token

        token_uuid, session_uuid = self._dao.token.create(token_payload, session_payload)
        token = Token(token_uuid, session_uuid=session_uuid, **token_payload)

        event = SessionCreatedEvent(session_uuid, user_uuid=auth_id, **session_payload)
        self._bus_publisher.publish(event)

        return token

    def _get_tenant_list(self, tenant_uuid):
        if not tenant_uuid:
            return []

        tenant_uuids = self._tenant_tree.list_nodes(tenant_uuid)
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

    def get(self, token_uuid, required_acl):
        token_data = self._dao.token.get(token_uuid)
        if not token_data:
            raise UnknownTokenException()

        id_ = token_data.pop('uuid')
        token = Token(id_, **token_data)

        if token.is_expired():
            raise UnknownTokenException()

        if not token.matches_required_acl(required_acl):
            raise MissingACLTokenException(required_acl)

        return token

    def _get_acl_templates(self, backend_name):
        policy_name = self._backend_policies.get(backend_name)
        if not policy_name:
            return []

        matching_policies = self._dao.policy.get(name=policy_name, limit=1)
        for policy in matching_policies:
            return policy['acl_templates']

        logger.info('Unknown policy name "%s" configured for backend "%s"', policy_name, backend_name)
        return []
