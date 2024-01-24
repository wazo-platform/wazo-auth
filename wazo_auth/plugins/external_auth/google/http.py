# Copyright 2019-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import time
from datetime import datetime
from threading import Thread

from flask import request
from marshmallow import ValidationError
from requests_oauthlib import OAuth2Session

from wazo_auth import http
from wazo_auth.exceptions import UserParamException
from wazo_auth.flask_helpers import Tenant

from .helpers import get_timestamp_expiration
from .schemas import GoogleSchema
from .websocket_oauth2 import WebSocketOAuth2

logger = logging.getLogger(__name__)

# Allow token scope to not match requested scope.
# (Requests-OAuthlib raises exception on scope mismatch by default.)
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
os.environ['OAUTHLIB_IGNORE_SCOPE_CHANGE'] = '1'


class GoogleAuth(http.AuthResource):
    auth_type = 'google'

    def __init__(self, external_auth_service, user_service, config):
        self.authorization_base_url = config[self.auth_type]['authorization_base_url']
        self.external_auth_service = external_auth_service
        self.redirect_uri = config[self.auth_type]['redirect_uri']
        self.scope = config[self.auth_type]['scope']
        self.token_url = config[self.auth_type]['token_url']
        self.user_service = user_service
        self.websocket_host = config[self.auth_type]['websocket_host']
        logger.debug('websocket_host %s', self.websocket_host)

    @http.required_acl('auth.users.{user_uuid}.external.google.create')
    def post(self, user_uuid):
        try:
            args = GoogleSchema().load(request.get_json())
        except ValidationError as e:
            raise UserParamException.from_errors(e.messages)

        client_id, client_secret = self._get_external_config()
        self.user_service.get_user(user_uuid)
        self.oauth2 = OAuth2Session(
            client_id, scope=self.scope, redirect_uri=self.redirect_uri
        )

        if args.get('scope'):
            self.oauth2.scope = args.get('scope')

        logger.debug('User(%s) is creating an authorize url for Google', str(user_uuid))

        authorization_url, state = self.oauth2.authorization_url(
            self.authorization_base_url, access_type='offline', prompt='consent'
        )
        logger.debug('Authorization url : %s', authorization_url)

        self.websocket = WebSocketOAuth2(
            host=self.websocket_host,
            auth=self.oauth2,
            external_auth=self.external_auth_service,
            client_secret=client_secret,
            token_url=self.token_url,
            auth_type=self.auth_type,
        )

        # TODO find something better than a thread per request
        websocket_thread = Thread(
            target=self.websocket.run, args=(state, user_uuid), name='websocket_thread'
        )
        websocket_thread.daemon = True
        websocket_thread.start()
        import time

        time.sleep(0.1)

        return {'authorization_url': authorization_url, 'state': state}, 201

    @http.required_acl('auth.users.{user_uuid}.external.google.read')
    def get(self, user_uuid):
        data = self.external_auth_service.get(user_uuid, self.auth_type)

        expiration = data.get('token_expiration')

        if self._is_token_expired(expiration):
            return self._refresh_token(user_uuid, data)

        return GoogleSchema().dump(data)

    @http.required_acl('auth.users.{user_uuid}.external.google.delete')
    def delete(self, user_uuid):
        self.external_auth_service.delete(user_uuid, self.auth_type)
        return '', 204

    def _is_token_expired(self, token_expiration):
        if token_expiration is None:
            return True
        return time.mktime(datetime.now().timetuple()) + 30 > token_expiration

    def _refresh_token(self, user_uuid, data):
        client_id, client_secret = self._get_external_config()
        oauth2 = OAuth2Session(client_id, token=data)
        token_data = oauth2.refresh_token(
            self.token_url, client_id=client_id, client_secret=client_secret
        )

        data['refresh_token'] = token_data['refresh_token']
        data['access_token'] = token_data['access_token']
        data['token_expiration'] = get_timestamp_expiration(token_data['expires_in'])
        data['scope'] = token_data['scope']

        self.external_auth_service.update(user_uuid, self.auth_type, data)

        return GoogleSchema().dump(data)

    def _get_external_config(self):
        tenant = Tenant.autodetect()
        config = self.external_auth_service.get_config(self.auth_type, tenant.uuid)

        return config.get('client_id'), config.get('client_secret')
