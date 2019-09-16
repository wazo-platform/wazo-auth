# Copyright 2015-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from flask import request
import marshmallow

from wazo_auth import exceptions, http
from . import schemas

logger = logging.getLogger(__name__)


class BaseResource(http.ErrorCatchingResource):

    def __init__(self, token_service, user_service, authentication_service):
        self._token_service = token_service
        self._user_service = user_service
        self._authentication_service = authentication_service


class Tokens(BaseResource):

    def post(self):
        user_agent = request.headers.get('User-Agent', '')
        remote_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

        try:
            args = schemas.TokenRequestSchema().load(request.get_json(force=True))
        except marshmallow.ValidationError as e:
            return http._error(400, str(e.messages))

        if request.authorization:
            args['login'] = request.authorization.username
            args['password'] = request.authorization.password

        session_type = request.headers.get('Wazo-Session-Type', '').lower()
        args['mobile'] = True if session_type == 'mobile' else False
        args['user_agent'] = user_agent
        args['remote_addr'] = remote_addr

        try:
            backend, login = self._authentication_service.verify_auth(args)
        except (
            exceptions.NoSuchBackendException,
            exceptions.InvalidUsernamePassword,
            exceptions.UnknownRefreshToken,
        ) as e:
            logger.info('failed login %s from %s %s', e, remote_addr, user_agent)
            return http._error(401, 'Authentication Failed')

        token = self._token_service.new_token(backend, login, args)

        return {'data': token.to_dict()}, 200


class Token(BaseResource):

    def delete(self, token_uuid):
        self._token_service.remove_token(token_uuid)

        return {'data': {'message': 'success'}}

    def get(self, token_uuid):
        scope = request.args.get('scope')
        tenant = request.args.get('tenant')

        token = self._token_service.get(token_uuid, scope).to_dict()
        self._assert_token_has_tenant_permission(token, tenant)

        return {'data': token}

    def head(self, token_uuid):
        scope = request.args.get('scope')
        tenant = request.args.get('tenant')

        token = self._token_service.get(token_uuid, scope).to_dict()
        self._assert_token_has_tenant_permission(token, tenant)

        return '', 204

    def _assert_token_has_tenant_permission(self, token, tenant):
        if not tenant:
            return

        # TODO: when the ldap_user gets remove all tokens will have a UUID
        user_uuid = token['metadata'].get('uuid')
        if not user_uuid:
            # Fallback on the token data since this is not a user token
            visible_tenants = set(t['uuid'] for t in token['metadata']['tenants'])
            if tenant not in visible_tenants:
                raise exceptions.MissingTenantTokenException(tenant)
            else:
                return

        if not self._user_service.user_has_sub_tenant(user_uuid, tenant):
            raise exceptions.MissingTenantTokenException(tenant)
