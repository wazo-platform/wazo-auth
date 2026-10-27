# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
from threading import Thread

import websocket

logger = logging.getLogger(__name__)


class RelayListener(Thread):
    """Waits on the OAuth2 relay for the authorization code of one state."""

    def __init__(self, host, state, on_code):
        super().__init__(name='salesforce_relay', daemon=True)
        self._url = f'{host}/ws/{state}'
        self._on_code = on_code

    def run(self):
        ws = websocket.WebSocketApp(
            self._url, on_message=self._on_message, on_error=self._on_error
        )
        try:
            ws.run_forever()
        finally:
            ws.close()

    def _on_message(self, ws, message):
        ws.close()
        self._on_code(json.loads(message).get('code'))

    def _on_error(self, ws, error):
        logger.error('Salesforce relay error: %s', type(error).__name__)
