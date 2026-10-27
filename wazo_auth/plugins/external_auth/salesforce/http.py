# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import time

import marshmallow
import requests
from flask import request
from oauthlib.oauth2 import OAuth2Error, WebApplicationClient
from requests_oauthlib import OAuth2Session

from wazo_auth import http
from wazo_auth.database.helpers import commit_or_rollback
from wazo_auth.exceptions import (
    APIException,
    ExternalAuthAlreadyExists,
    UnknownExternalAuthException,
    UserParamException,
)
from wazo_auth.flask_helpers import Tenant

from .relay import RelayListener
from .schemas import SalesforceLinkSchema, SalesforcePostSchema
from .token import is_expired, new_link, refreshed_link

logger = logging.getLogger(__name__)

# Salesforce grants scopes other than those requested, which requests-oauthlib
# refuses unless these are set; process-wide, so set here too.
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
os.environ['OAUTHLIB_IGNORE_SCOPE_CHANGE'] = '1'

TOKEN_REQUEST_TIMEOUT = 10
# What requests-oauthlib raises on a token endpoint that refuses, fails or is gone
TOKEN_ERRORS = (OAuth2Error, requests.RequestException, ValueError)
# What a concurrent request replacing the same link makes `update` raise
REPLACED_ERRORS = (ExternalAuthAlreadyExists, UnknownExternalAuthException)
PKCE_VERIFIER_LENGTH = 64


class SalesforceLinkExpired(APIException):
    def __init__(self, user_uuid):
        msg = 'The Salesforce link has expired and cannot be refreshed: link again'
        details = {'user_uuid': str(user_uuid)}
        super().__init__(404, msg, 'salesforce-link-expired', details, 'users')


class SalesforceRefreshFailed(APIException):
    def __init__(self, user_uuid):
        msg = 'Salesforce refused or did not answer the token refresh'
        details = {'user_uuid': str(user_uuid)}
        super().__init__(502, msg, 'salesforce-refresh-failed', details, 'users')


def fetch_first_token(oauth2, token_url, client_secret, code, code_verifier):
    return oauth2.fetch_token(
        token_url,
        client_secret=client_secret,
        code=code,
        code_verifier=code_verifier,
        include_client_id=True,
        timeout=TOKEN_REQUEST_TIMEOUT,
    )


class SalesforceAuth(http.AuthResource):
    auth_type = 'salesforce'

    def __init__(self, external_auth_service, user_service, section):
        self.authorization_base_url = section['authorization_base_url']
        self.redirect_uri = section['redirect_uri']
        self.scope = section['scope']
        self.token_url = section['token_url']
        self.websocket_host = section['websocket_host']
        self.access_token_lifetime = section['access_token_lifetime']
        self.external_auth_service = external_auth_service
        self.user_service = user_service

    @http.required_acl('auth.users.{user_uuid}.external.salesforce.create')
    def post(self, user_uuid):
        try:
            args = SalesforcePostSchema().load(request.get_json(force=True))
        except marshmallow.ValidationError as e:
            raise UserParamException.from_errors(e.messages)

        tenant_uuid = self._assert_user_visible(user_uuid)
        client_id, client_secret = self._get_app_credentials(tenant_uuid)

        client = WebApplicationClient(client_id)
        code_verifier = client.create_code_verifier(PKCE_VERIFIER_LENGTH)
        oauth2 = OAuth2Session(
            client=client,
            scope=args.get('scope') or self.scope,
            redirect_uri=self.redirect_uri,
        )
        authorization_url, state = oauth2.authorization_url(
            self.authorization_base_url,
            code_challenge=client.create_code_challenge(code_verifier, 'S256'),
            code_challenge_method='S256',
        )

        def on_code(code):
            self._complete_link(
                oauth2, client_secret, code_verifier, user_uuid, tenant_uuid, code
            )

        RelayListener(self.websocket_host, state, on_code).start()
        logger.info(
            'User(%s) of tenant %s is linking a Salesforce account',
            user_uuid,
            tenant_uuid,
        )
        return {'authorization_url': authorization_url, 'state': state}, 201

    @http.required_acl('auth.users.{user_uuid}.external.salesforce.read')
    def get(self, user_uuid):
        self._assert_user_visible(user_uuid)
        link = self.external_auth_service.get(user_uuid, self.auth_type)
        if is_expired(link.get('token_expiration'), time.time()):
            link = self._refresh(user_uuid, link)
        return SalesforceLinkSchema().dump(link)

    @http.required_acl('auth.users.{user_uuid}.external.salesforce.delete')
    def delete(self, user_uuid):
        self._assert_user_visible(user_uuid)
        self.external_auth_service.delete(user_uuid, self.auth_type)
        return '', 204

    def _complete_link(
        self, oauth2, client_secret, code_verifier, user_uuid, tenant_uuid, code
    ):
        try:
            token_data = fetch_first_token(
                oauth2, self.token_url, client_secret, code, code_verifier
            )
            link = new_link(token_data, self.access_token_lifetime, time.time())
        except TOKEN_ERRORS as e:
            logger.warning(
                'User(%s) of tenant %s: Salesforce refused the code (%s)',
                user_uuid,
                tenant_uuid,
                type(e).__name__,
            )
            commit_or_rollback()
            return

        # the link remembers its app, so a refresh uses the same one
        link['app_tenant_uuid'] = tenant_uuid
        try:
            try:
                self.external_auth_service.create(user_uuid, self.auth_type, link)
            except ExternalAuthAlreadyExists:
                self.external_auth_service.update(user_uuid, self.auth_type, link)
        except Exception as e:
            logger.error(
                'User(%s) of tenant %s: Salesforce link not stored (%s)',
                user_uuid,
                tenant_uuid,
                type(e).__name__,
            )
        else:
            logger.info(
                'User(%s) of tenant %s linked a Salesforce account',
                user_uuid,
                tenant_uuid,
            )
        finally:
            commit_or_rollback()

    def _refresh(self, user_uuid, link):
        tenant_uuid = link.get('app_tenant_uuid') or Tenant.autodetect().uuid
        if not link.get('refresh_token'):
            logger.info(
                'User(%s) of tenant %s: Salesforce link expired, no refresh token',
                user_uuid,
                tenant_uuid,
            )
            raise SalesforceLinkExpired(user_uuid)

        client_id, client_secret = self._get_app_credentials(tenant_uuid)
        oauth2 = OAuth2Session(client_id, token=link)
        try:
            token_data = oauth2.refresh_token(
                self.token_url,
                client_id=client_id,
                client_secret=client_secret,
                timeout=TOKEN_REQUEST_TIMEOUT,
            )
        except TOKEN_ERRORS as e:
            logger.warning(
                'User(%s) of tenant %s: Salesforce token refresh failed (%s)',
                user_uuid,
                tenant_uuid,
                type(e).__name__,
            )
            raise SalesforceRefreshFailed(user_uuid)

        link = refreshed_link(link, token_data, self.access_token_lifetime, time.time())
        try:
            self.external_auth_service.update(user_uuid, self.auth_type, link)
        except REPLACED_ERRORS:
            # another request replaced the link meanwhile; this token is valid too
            logger.info(
                'User(%s) of tenant %s: Salesforce link replaced during the refresh',
                user_uuid,
                tenant_uuid,
            )
            return link
        logger.info(
            'User(%s) of tenant %s: Salesforce token refreshed', user_uuid, tenant_uuid
        )
        return link

    def _assert_user_visible(self, user_uuid):
        tenant_uuid = Tenant.autodetect().uuid
        self.user_service.assert_user_in_subtenant(tenant_uuid, user_uuid)
        return tenant_uuid

    def _get_app_credentials(self, tenant_uuid):
        config = self.external_auth_service.get_config(self.auth_type, tenant_uuid)
        return config.get('client_id'), config.get('client_secret')
