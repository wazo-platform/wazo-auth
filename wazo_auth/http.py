# Copyright 2015-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import functools
import logging
import time

from flask import current_app
from flask_restful import Resource
from xivo.rest_api_helpers import handle_api_exception
from xivo.auth_verifier import (
    AuthVerifier,
    extract_token_id_from_query_or_header,
    required_acl as _required_acl,
    Unauthorized,
)

from . import exceptions

logger = logging.getLogger(__name__)

required_acl = _required_acl


def _error(code, msg):
    return {'reason': [msg], 'timestamp': [time.time()], 'status_code': code}, code


class AuthClientFacade:
    class TokenCommand:
        def is_valid(self, token_id, required_acl):
            try:
                current_app.config['token_service'].get(token_id, required_acl)
                return True
            except exceptions.UnknownTokenException:
                return False
            except exceptions.MissingACLTokenException:
                return False

        def get(self, token_id, required_acl=None):
            try:
                return (
                    current_app.config['token_service']
                    .get(token_id, required_acl)
                    .to_dict()
                )
            except exceptions.UnknownTokenException:
                raise Unauthorized(token_id)

    class UsersCommand:
        def get(self, user_uuid):
            return current_app.config['user_service'].get_user(user_uuid)

        def get_tenants(self, user_uuid):
            tenants = current_app.config['user_service'].list_tenants(user_uuid)
            return {
                'items': [
                    {'uuid': tenant['uuid'], 'name': tenant['name']}
                    for tenant in tenants
                ]
            }

    def __init__(self):
        self.token = self.TokenCommand()
        self.users = self.UsersCommand()


auth_verifier = AuthVerifier(extract_token_id=extract_token_id_from_query_or_header)
auth_verifier.set_client(AuthClientFacade())


def handle_manager_exception(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except exceptions.TokenServiceException as error:
            return _error(error.code, str(error))

    return wrapper


class ErrorCatchingResource(Resource):
    method_decorators = [
        handle_manager_exception,
        handle_api_exception,
    ] + Resource.method_decorators


class AuthResource(ErrorCatchingResource):
    auth_verifier = auth_verifier
    method_decorators = [
        auth_verifier.verify_token
    ] + ErrorCatchingResource.method_decorators
