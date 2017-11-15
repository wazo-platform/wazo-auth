# -*- coding: utf-8 -*-
#
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
#
# SPDX-License-Identifier: GPL-3.0+

import functools
import logging
import time

from flask import current_app, Flask, request, make_response
from flask_cors import CORS
from flask_restful import Api, Resource
from stevedore.named import NamedExtensionManager
from xivo.rest_api_helpers import handle_api_exception
from pkg_resources import resource_string
from xivo import http_helpers, plugin_helpers

from . import exceptions, schemas

logger = logging.getLogger(__name__)


def _error(code, msg):
    return {'reason': [msg],
            'timestamp': [time.time()],
            'status_code': code}, code


def required_acl(scope):
    def wrap(f):
        @functools.wraps(f)
        def wrapped_f(*args, **kwargs):
            try:
                token = request.headers.get('X-Auth-Token', '')
                current_app.config['token_manager'].get(token, scope)
            except exceptions.ManagerException:
                return _error(401, 'Unauthorized')
            return f(*args, **kwargs)
        return wrapped_f
    return wrap


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


class Swagger(Resource):

    api_package = "wazo_auth.swagger"
    api_filename = "api.yml"
    api_path = "/api/api.yml"

    @classmethod
    def add_resource(cls, api):
        api.add_resource(cls, cls.api_path)

    def get(self):
        try:
            api_spec = resource_string(self.api_package, self.api_filename)
        except IOError:
            return {'error': "API spec does not exist"}, 404

        return make_response(api_spec, 200, {'Content-Type': 'application/x-yaml'})


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
    api.add_resource(Swagger, '/api/api.yml')
    app.config.update(config)

    if cors_enabled:
        CORS(app, **cors_config)

    app.config['token_manager'] = dependencies['token_manager']
    app.config['backends'] = dependencies['backends']

    app.after_request(http_helpers.log_request)

    return app
