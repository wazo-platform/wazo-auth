# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json
from contextlib import contextmanager
from unittest.mock import patch

import requests

CLIENT_ID = 'the-client-id'
CLIENT_SECRET = 'the-client-secret-value'
ACCESS_TOKEN = 'the-access-token-value'
NEW_ACCESS_TOKEN = 'the-new-access-token-value'
REFRESH_TOKEN = 'the-refresh-token-value'
CODE = 'the-authorization-code-value'
INSTANCE_URL = 'https://example.my.salesforce.com'
TOKEN_URL = 'https://login.example.com/services/oauth2/token'

CONFIG = {
    'salesforce': {
        'authorization_base_url': 'https://login.example.com/services/oauth2/authorize',
        'token_url': TOKEN_URL,
        'redirect_uri': 'https://oauth.example.com/salesforce/authorize',
        'scope': ['api', 'refresh_token'],
        'websocket_host': 'wss://oauth.example.com',
        'access_token_lifetime': 7200,
    }
}


def salesforce_token_body(**overrides):
    body = {
        'access_token': ACCESS_TOKEN,
        'refresh_token': REFRESH_TOKEN,
        'instance_url': INSTANCE_URL,
        'id': 'https://login.example.com/id/00D/005',
        'token_type': 'Bearer',
        'issued_at': '1702123456789',
        'signature': 'c2lnbmF0dXJl',
        'scope': 'api refresh_token id',
    }
    body.update(overrides)
    return {key: value for key, value in body.items() if value is not None}


class FakeTokenEndpoint:
    """Answers, in order, every request sent through `requests`."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.requests = []

    def send(self, adapter, request, **kwargs):
        self.requests.append(request)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        status, body = answer
        response = requests.Response()
        response.status_code = status
        if isinstance(body, dict):
            response._content = json.dumps(body).encode()
            response.headers['Content-Type'] = 'application/json'
        else:
            response._content = body.encode()
            response.headers['Content-Type'] = 'text/html'
        response.url = request.url
        response.request = request
        return response

    @contextmanager
    def serving(self):
        with patch(
            'requests.adapters.HTTPAdapter.send', autospec=True, side_effect=self.send
        ):
            yield self
