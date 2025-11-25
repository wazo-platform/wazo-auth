# Copyright 2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from datetime import datetime, timezone, timedelta
from google import genai

from wazo_auth import http
from wazo_auth.flask_helpers import Tenant

# from .schemas import GeminiSchema

logger = logging.getLogger(__name__)

class GeminiAuth(http.AuthResource):
    auth_type = 'gemini'

    def __init__(self, external_auth_service):
        self.external_auth_service = external_auth_service

    @http.required_acl('auth.users.{user_uuid}.external.gemini.read')
    def get(self, user_uuid):
        # TODO check if user_uuid exists / is valid
        tenant = Tenant.autodetect()
        config = self.external_auth_service.get_config(self.auth_type, tenant.uuid)

        try:
            api_key = config['api_key']
            theme = config['theme']
            ephemeral_timeout = config['ephemeral_timeout']
        except KeyError:
            return 'Missing required configuration options: [api_key, theme, ephemeral_timeout]', 400

        now = datetime.now(tz=timezone.utc)
        client = genai.Client(api_key=api_key)
        token = client.auth_tokens.create(config={
            'uses': 1,
            'expire_time': now + timedelta(seconds=ephemeral_timeout),
            'new_session_expire_time': now + timedelta(minutes=1),
            'http_options': {'api_version': 'v1alpha'},
        })
        return {'token': token.name, 'theme': theme}
