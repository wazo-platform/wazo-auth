# Copyright 2015-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from flask import request
from wazo_auth import exceptions, http
from . import schemas

logger = logging.getLogger(__name__)


class BaseResource(http.ErrorCatchingResource):

    def __init__(self, token_manager, backends, user_service):
        self._backends = backends
        self._token_manager = token_manager
        self._user_service = user_service


class Tokens(BaseResource):

    def post(self):
        if request.authorization:
            login = request.authorization.username
            password = request.authorization.password
        else:
            login = ''
            password = ''

        args, error = schemas.TokenRequestSchema().load(request.get_json(force=True))
        if error:
            return http._error(400, str(error))

        backend_name = args['backend']
        try:
            backend = self._backends[backend_name].obj
        except KeyError:
            logger.debug('Backend not found: "%s"', backend_name)
            return http._error(401, 'Authentication Failed')

        if not backend.verify_password(login, password, args):
            logger.debug('Invalid password for user "%s" in backend "%s"', login, backend_name)
            return http._error(401, 'Authentication Failed')

        token = self._token_manager.new_token(backend, login, args)

        return {'data': token.to_dict()}, 200


class Token(BaseResource):

    def delete(self, token):
        self._token_manager.remove_token(token)

        return {'data': {'message': 'success'}}

    def get(self, token):
        scope = request.args.get('scope')
        tenant = request.args.get('tenant')

        token = self._token_manager.get(token, scope).to_dict()
        self._assert_token_has_tenant_permission(token, tenant)

        return {'data': token}

    def head(self, token):
        scope = request.args.get('scope')
        tenant = request.args.get('tenant')

        token = self._token_manager.get(token, scope).to_dict()
        self._assert_token_has_tenant_permission(token, tenant)

        return '', 204

    def _assert_token_has_tenant_permission(self, token, tenant):
        if not tenant:
            return

        # TODO: when the xivo_admin, xivo_service and ldap_user gets remove all tokens will have a UUID
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
