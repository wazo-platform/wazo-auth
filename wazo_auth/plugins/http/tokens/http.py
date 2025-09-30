# Copyright 2015-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from base64 import b64decode

import marshmallow
from flask import request

from wazo_auth import exceptions, http
from wazo_auth.flask_helpers import Tenant

from . import schemas

logger = logging.getLogger(__name__)


class BaseResource(http.ErrorCatchingResource):
    def __init__(
        self,
        token_service,
        user_service,
        saml_service,
        authentication_service,
        backends,
    ):
        self._token_service = token_service
        self._user_service = user_service
        self._saml_service = saml_service
        self._authentication_service = authentication_service
        self._backends = backends


class _BaseRefreshTokens(http.AuthResource):
    def __init__(self, token_service, user_service, authentication_service):
        self._token_service = token_service
        self._user_service = user_service
        self._authentication_service = authentication_service

    def _get(self, user_uuid, recurse=False):
        scoping_tenant = Tenant.autodetect()

        self._assert_user_is_visible_in_tenant(user_uuid, scoping_tenant.uuid)

        search_params = self._build_search_params(
            user_uuid, scoping_tenant.uuid, recurse
        )

        refresh_tokens = self._token_service.list_refresh_tokens(**search_params)

        return {
            'total': self._token_service.count_refresh_tokens(
                filtered=False, **search_params
            ),
            'filtered': self._token_service.count_refresh_tokens(
                filtered=True, **search_params
            ),
            'items': schemas.RefreshTokenSchema().dump(refresh_tokens, many=True),
        }

    def _assert_user_is_visible_in_tenant(self, user_uuid, scoping_tenant_uuid):
        self._user_service.get_user(user_uuid, scoping_tenant_uuid)

    def _delete(self, user_uuid, client_id):
        scoping_tenant = Tenant.autodetect()

        self._assert_user_is_visible_in_tenant(user_uuid, scoping_tenant.uuid)

        self._token_service.delete_refresh_token(
            scoping_tenant.uuid, user_uuid, client_id
        )

    def _find_user_uuid(self):
        token = request.headers.get('X-Auth-Token') or request.args.get('token')
        token_data = self._token_service.get(token, required_access=None)
        return token_data.metadata.get('uuid')

    def _build_search_params(
        self, user_uuid=None, scoping_tenant_uuid=None, recurse=None
    ):
        try:
            search_params = schemas.RefreshTokenListSchema().load(request.args)
        except marshmallow.ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        search_params['scoping_tenant_uuid'] = scoping_tenant_uuid
        if user_uuid is not None:
            search_params['user_uuid'] = user_uuid

        if recurse is not None:
            search_params['recurse'] = recurse

        return search_params


class UserMeRefreshTokens(_BaseRefreshTokens):
    @http.required_acl('auth.users.me.tokens.read')
    def get(self):
        user_uuid = self._find_user_uuid()
        return self._get(user_uuid)


class UserMeRefreshToken(_BaseRefreshTokens):
    @http.required_acl('auth.users.me.tokens.{client_id}.delete')
    def delete(self, client_id):
        user_uuid = self._find_user_uuid()
        self._delete(user_uuid, client_id)
        return '', 204


class UserRefreshTokens(_BaseRefreshTokens):
    @http.required_acl('auth.users.{user_uuid}.tokens.read')
    def get(self, user_uuid):
        return self._get(str(user_uuid), recurse=True)


class UserRefreshToken(_BaseRefreshTokens):
    @http.required_acl('auth.users.{user_uuid}.tokens.{client_id}.delete')
    def delete(self, user_uuid, client_id):
        self._delete(str(user_uuid), client_id)
        return '', 204


class RefreshTokens(_BaseRefreshTokens):
    @http.required_acl('auth.tokens.read')
    def get(self):
        scoping_tenant = Tenant.autodetect()

        search_params = self._build_search_params(
            user_uuid=None,
            scoping_tenant_uuid=scoping_tenant.uuid,
        )

        refresh_tokens = self._token_service.list_refresh_tokens(**search_params)

        return {
            'total': self._token_service.count_refresh_tokens(
                filtered=False, **search_params
            ),
            'filtered': self._token_service.count_refresh_tokens(
                filtered=True, **search_params
            ),
            'items': schemas.RefreshTokenSchema().dump(refresh_tokens, many=True),
        }


class Tokens(BaseResource):
    def _get_login_password(self):
        # This method is a workaround
        # to support latin-1(ISO-8859-1) charset in http basic auth
        # since werkzeug `request.authorization` only supports utf-8
        # with versions:
        # 2.0.2 (bookworm)
        # see https://wazo-dev.atlassian.net/browse/WP-1084
        error = None, None

        authorization = request.headers.get('Authorization')
        if not authorization:
            return error

        if not authorization.startswith('Basic '):
            return error

        _, encoded_login_password = authorization.split('Basic ', 1)
        login_password = b64decode(encoded_login_password)

        charsets = ['utf-8', 'latin']
        for charset in charsets:
            try:
                login_password = login_password.decode(charset)
                break
            except UnicodeDecodeError:
                continue
        else:
            return error

        if ':' not in login_password:
            return error

        return login_password.split(':', 1)

    def post(self):
        user_agent = request.headers.get('User-Agent', '')
        remote_addr = request.remote_addr

        try:
            args = schemas.TokenRequestSchema().load(request.get_json(force=True))
        except marshmallow.ValidationError as e:
            return http._error(400, str(e.messages))

        login, password = self._get_login_password()
        if login and password:
            args['login'] = login
            args['password'] = password

        session_type = request.headers.get('Wazo-Session-Type', '').lower()
        args['mobile'] = True if session_type == 'mobile' else False
        args['user_agent'] = user_agent
        args['remote_addr'] = remote_addr

        try:
            backend, login = self._authentication_service.verify_auth(args)
        except (
            exceptions.InvalidUsernamePassword,
            exceptions.UnknownRefreshToken,
            exceptions.NoMatchingSAMLSession,
            exceptions.UnauthorizedAuthenticationMethod,
            exceptions.UnknownLoginException,
            exceptions.InvalidLoginRequest,
        ) as e:
            logger.info(
                'Failed login: %s from %s using agent "%s"',
                e,
                remote_addr,
                user_agent,
            )
            logger.debug('authentication failed: %s', e)
            return http._error(401, 'Authentication Failed')

        token = self._token_service.new_token(backend, login, args)
        logger.info(
            'Successful login: %s got token %s from %s using agent "%s"',
            login,
            token.token_redacted(),
            remote_addr,
            user_agent,
        )
        if token.refresh_token and args.get('saml_session_id'):
            self._saml_service.update_refresh_token(
                token.refresh_token, args.get('saml_session_id')
            )
            self._saml_service.invalidate_saml_session_id(args.get('saml_session_id'))

        return {'data': token.to_dict()}, 200


class Token(BaseResource):
    def delete(self, token_uuid):
        self._token_service.remove_token(token_uuid)

        return {'data': {'message': 'success'}}

    def get(self, token_uuid):
        scope = request.args.get('scope')
        tenant = request.args.get('tenant')

        token = self._token_service.get(token_uuid, scope).to_dict()
        self._token_service.assert_has_tenant_permission(token, tenant)

        return {'data': token}

    def head(self, token_uuid):
        scope = request.args.get('scope')
        tenant = request.args.get('tenant')

        token = self._token_service.get(token_uuid, scope).to_dict()
        self._token_service.assert_has_tenant_permission(token, tenant)

        return '', 204


class TokenScopesCheck(BaseResource):
    def post(self, token_uuid):
        try:
            args = schemas.TokenScopesRequestSchema().load(request.get_json(force=True))
        except marshmallow.ValidationError as e:
            return http._error(400, str(e.messages))

        token, scopes_statuses = self._token_service.check_scopes(
            token_uuid, args['scopes']
        )
        self._token_service.assert_has_tenant_permission(
            token.to_dict(), args['tenant_uuid']
        )
        return {'scopes': scopes_statuses}, 200
