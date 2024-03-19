# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from flask import request

from wazo_auth import http


class SAMLACS(http.ErrorCatchingResource):
    def __init__(
        self, token_service, user_service, auth_service, config, backend_proxy
    ):
        self._token_service = token_service
        self._user_service = user_service
        self._auth_service = auth_service
        self._config = (
            config  # Can be used to access to content of the configuration files
        )
        self._backend_proxy = backend_proxy

    def post(self):
        # Do you SAML validation here
        # Find the user's email adress from the SAML document. The username could also
        # be used if Wazo and the identity provider are configured with the same username
        login = email_address = 'alice@wazo.io'
        backend_name = 'wazo_user'
        args = {
            'user_agent': request.headers.get('User-Agent', ''),
            'login': email_address,
            'mobile': True,
            'remote_addr': request.remote_addr,
        }

        # The following headers are expected on the ACS request
        # User-Agent
        # Wazo-Session-Type
        # The following values should be added to the ACS payload by the Agent
        # backend: defaults to wazo_user
        # expiration: token validity in seconds
        # access_type: online or offline
        # client_id: required if access_type is offline to create a request token

        token = self._token_service.new_token(
            self._backend_proxy.get(backend_name), login, args
        )
        return {'data': token.to_dict()}, 200


class SAMLSSO(http.ErrorCatchingResource):
    def __init__(
        self, token_service, user_service, auth_service, config, wazo_user_backend
    ):
        self._token_service = token_service
        self._user_service = user_service
        self._auth_service = auth_service
        self._config = config
        self._backend = wazo_user_backend

    def post(self):
        pass
