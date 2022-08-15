# Copyright 2019-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
from threading import Thread

import websocket

from wazo_auth.exceptions import ExternalAuthAlreadyExists
from wazo_auth.database.helpers import commit_or_rollback
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
        self.ws = None

    def run(self, state, user_uuid):
        self.user_uuid = user_uuid

        self.ws = websocket.WebSocketApp(
            f'{self.host}/ws/{state}',
            on_message=self._on_message,
            on_error=self._on_error,
            on_close=self._on_close,
        )
        logger.debug('WebSocketOAuth2 opened.')
        try:
            self.ws.run_forever()
        finally:
            if self.ws:
                self.ws.close()
                self.ws = None

    def _on_message(self, message):
        logger.debug(
            "Confirmation has been received on websocketOAuth, message : %s.", message
        )
        msg = json.loads(message)
        if self.ws:
            self.ws.close()
            self.ws = None
        self.create_first_token(self.user_uuid, msg.get('code'))
        commit_or_rollback()

    def _on_error(self, error):
        logger.error(error)

    def _on_close(self):
        logger.debug("WebsocketOAuth closed.")

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
        logger.debug('Microsoft token created.')
        try:
            self.external_auth_service.create(user_uuid, self.auth_type, data)
        except ExternalAuthAlreadyExists:
            self.external_auth_service.update(user_uuid, self.auth_type, data)
