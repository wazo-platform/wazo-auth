# -*- coding: utf-8 -*-
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import functools
import logging
import time

from flask import current_app, Flask, request
from flask_cors import CORS
from flask_restful import Api, Resource
from xivo.rest_api_helpers import handle_api_exception
from xivo.auth_verifier import AuthVerifier, required_acl
from xivo import http_helpers, plugin_helpers

from . import exceptions, schemas

logger = logging.getLogger(__name__)


def _error(code, msg):
    return {'reason': [msg],
            'timestamp': [time.time()],
            'status_code': code}, code


class AuthClientFacade(object):

    class TokenCommand(object):

        def is_valid(self, token_id, scope):
            try:
                current_app.config['token_manager'].get(token_id, scope)
                return True
            except exceptions.UnknownTokenException:
                return False
            except exceptions.MissingACLTokenException:
                return False

    def __init__(self):
        self.token = self.TokenCommand()


auth_verifier = AuthVerifier()
auth_verifier.set_client(AuthClientFacade())


def handle_manager_exception(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except exceptions.ManagerException as error:
            return _error(error.code, str(error))
    return wrapper


class ErrorCatchingResource(Resource):
    method_decorators = (
        [
            handle_manager_exception,
            handle_api_exception,
        ] + Resource.method_decorators
    )


class AuthResource(ErrorCatchingResource):
    method_decorators = [auth_verifier.verify_token] + ErrorCatchingResource.method_decorators


class Tokens(ErrorCatchingResource):

    def post(self):
        if request.authorization:
            login = request.authorization.username
            password = request.authorization.password
        else:
            login = ''
            password = ''

        args, error = schemas.TokenRequestSchema().load(request.get_json(force=True))
        if error:
            return _error(400, unicode(error))

        backend_name = args['backend']
        try:
            backend = current_app.config['backends'][backend_name].obj
        except KeyError:
            return _error(401, 'Authentication Failed')

        if not backend.verify_password(login, password, args):
            return _error(401, 'Authentication Failed')

        token = current_app.config['token_manager'].new_token(backend, login, args)

        return {'data': token.to_dict()}, 200


class Token(ErrorCatchingResource):

    def delete(self, token):
        current_app.config['token_manager'].remove_token(token)

        return {'data': {'message': 'success'}}

    def get(self, token):
        scope = request.args.get('scope')
        token = current_app.config['token_manager'].get(token, scope)
        return {'data': token.to_dict()}

    def head(self, token):
        scope = request.args.get('scope')
        token = current_app.config['token_manager'].get(token, scope)
        return '', 204


class Backends(ErrorCatchingResource):

    def get(self):
        return {'data': current_app.config['loaded_plugins']}


def new_app(dependencies):
    config = dependencies['config']
    cors_config = dict(config['rest_api']['cors'])
    cors_enabled = cors_config.pop('enabled')

    app = Flask('wazo-auth')
    http_helpers.add_logger(app, logger)
    api = Api(app, prefix='/0.1')

    dependencies['api'] = api
    plugin_helpers.load('wazo_auth.http', config['enabled_http_plugins'], dependencies)

    api.add_resource(Tokens, '/token')
    api.add_resource(Token, '/token/<string:token>')
    api.add_resource(Backends, '/backends')
    app.config.update(config)

    if cors_enabled:
        CORS(app, **cors_config)

    app.config['token_manager'] = dependencies['token_manager']
    app.config['backends'] = dependencies['backends']

    app.after_request(http_helpers.log_request)

    return app
