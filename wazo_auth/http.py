# Copyright 2015-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import cProfile
import functools
import logging
import os
import os.path
import time
from datetime import datetime

from flask import current_app, g, request
from flask_restful import Resource
from wazo_auth_client.exceptions import (
    InvalidTokenException,
    MissingPermissionsTokenException,
)
from werkzeug.local import LocalProxy as Proxy
from xivo.auth_verifier import Unauthorized
from xivo.auth_verifier import required_acl as _required_acl
from xivo.auth_verifier import required_tenant
from xivo.flask.auth_verifier import AuthVerifierFlask
from xivo.rest_api_helpers import handle_api_exception

from wazo_auth.database.helpers import commit_or_rollback

from . import exceptions
from .http_server import app

logger = logging.getLogger(__name__)


def _error(code, msg):
    return {'reason': [msg], 'timestamp': [time.time()], 'status_code': code}, code


class AuthClientFacade:
    class TokenCommand:
        def check(self, token_id, required_access, tenant=None):
            try:
                current_app.config['token_service'].get(token_id, required_access)
                return True
            except exceptions.UnknownTokenException:
                raise InvalidTokenException()
            except exceptions.MissingAccessTokenException:
                raise MissingPermissionsTokenException()

        def is_valid(self, token_id, required_access):
            try:
                current_app.config['token_service'].get(token_id, required_access)
                return True
            except exceptions.UnknownTokenException:
                return False
            except exceptions.MissingAccessTokenException:
                return False

        def get(self, token_id, required_access=None):
            try:
                return (
                    current_app.config['token_service']
                    .get(token_id, required_access)
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

    def set_token(self, token_uuid):
        # Mocked for helpers
        pass


def inject_auth_client(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        g.auth_client = AuthClientFacade()
        return func(*args, **kwargs)

    return wrapper


auth_verifier = AuthVerifierFlask()


def handle_manager_exception(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except exceptions.TokenServiceException as error:
            return _error(error.code, str(error))

    return wrapper


def trigger_profiling(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not current_app.config.get('profiling_enabled'):
            return func(*args, **kwargs)

        directory = '/tmp/wazo-profiling'
        if not os.path.exists(directory):
            os.makedirs(directory)

        with cProfile.Profile() as profile:
            result = func(*args, **kwargs)

        timestamp = datetime.now()
        request_path = 'api_auth' + request.path.replace('/', '_')
        file_name = f'{timestamp.isoformat()}-{request_path}.profile'
        profile.dump_stats(f'{directory}/{file_name}')
        return result

    return wrapper


class ProfilingResource(Resource):
    method_decorators = [
        trigger_profiling,
    ] + Resource.method_decorators


class ErrorCatchingResource(ProfilingResource):
    method_decorators = [
        handle_manager_exception,
        handle_api_exception,
    ] + ProfilingResource.method_decorators


class AuthResource(ErrorCatchingResource):
    auth_verifier = auth_verifier
    method_decorators = [
        auth_verifier.verify_tenant,
        auth_verifier.verify_token,
        inject_auth_client,
    ] + ErrorCatchingResource.method_decorators


def init_top_tenant(dao):
    top_tenant_uuid = dao.tenant.find_top_tenant()
    commit_or_rollback()
    app.config['top_tenant_uuid'] = top_tenant_uuid
    logger.debug('Initiated top tenant UUID: %s', top_tenant_uuid)


def get_top_tenant_uuid():
    if not app:
        raise Exception('Flask application not configured')

    tenant_uuid = app.config.get('top_tenant_uuid')
    if not tenant_uuid:
        raise exceptions.TopTenantNotInitialized()
    return tenant_uuid


def required_top_tenant():
    return required_tenant(top_tenant_uuid)


required_acl = _required_acl
top_tenant_uuid = Proxy(get_top_tenant_uuid)
