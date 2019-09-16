# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
from threading import Thread

import websocket

from wazo_auth.exceptions import ExternalAuthAlreadyExists
from .helpers import get_timestamp_expiration

logger = logging.getLogger(__name__)


class WebSocketOAuth2(Thread):
    def __init__(self, host, auth, external_auth, client_secret, token_url, auth_type):
        super().__init__()

        self.host = host
        self.oauth2 = auth
        self.external_auth_service = external_auth
        self.client_secret = client_secret
        self.token_url = token_url
        self.user_uuid = None
        self.auth_type = auth_type

    def run(self, state, user_uuid):
        self.user_uuid = user_uuid

        url = '{}/ws/{}'.format(self.host, state)
        self.ws = websocket.WebSocketApp(
            url,
            on_message=self._on_message,
            on_error=self._on_error,
            on_close=self._on_close,
        )
        logger.debug('Opening WebSocketOAuth2 %s', url)
        try:
            self.ws.run_forever()
        finally:
            self.ws.close()

    def _on_message(self, message):
        try:
            logger.debug(
                "Confirmation has been received on websocketOAuth, message : %s",
                message,
            )
            msg = json.loads(message)
            self.ws.close()
            self.create_first_token(self.user_uuid, msg.get('code'))
        except Exception as e:
            logger.error('error when receiving websocket event %s', e)

    def _on_error(self, error):
        logger.error(error)

    def _on_close(self):
        logger.debug("WebsocketOAuth closed")

    def create_first_token(self, user_uuid, code):
        logger.debug('Trying to fetch token on %s', self.token_url)
        token_data = self.oauth2.fetch_token(
            self.token_url, client_secret=self.client_secret, code=code
        )
        data = {
            'access_token': token_data['access_token'],
            'refresh_token': token_data['refresh_token'],
            'token_expiration': get_timestamp_expiration(token_data['expires_in']),
            'scope': token_data['scope'],
        }
        logger.debug('Google token created')
        try:
            self.external_auth_service.create(user_uuid, self.auth_type, data)
        except ExternalAuthAlreadyExists:
            self.external_auth_service.update(user_uuid, self.auth_type, data)
