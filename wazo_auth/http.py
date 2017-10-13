# -*- coding: utf-8 -*-
#
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import functools
import logging
import time

from flask import current_app, Flask, request, make_response
from flask.ext.cors import CORS
from flask_restful import Api, Resource
from marshmallow import Schema, fields, pre_load
from marshmallow.validate import Range
from xivo.mallow import fields as xfields
from xivo.mallow import validate
from xivo.rest_api_helpers import APIException, handle_api_exception
from pkg_resources import resource_string
from xivo import http_helpers

from wazo_auth.exceptions import ManagerException

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
            except ManagerException:
                return _error(401, 'Unauthorized')
            return f(*args, **kwargs)
        return wrapped_f
    return wrap


def handle_manager_exception(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ManagerException as error:
            return _error(error.code, str(error))
    return wrapper


class ErrorCatchingResource(Resource):
    method_decorators = (
        [
            handle_manager_exception,
            handle_api_exception,
        ] + Resource.method_decorators
    )


class Policies(ErrorCatchingResource):

    @required_acl('auth.policies.create')
    def post(self):
        data = request.get_json()
        policy_manager = current_app.config['policy_manager']
        policy = policy_manager.create(data)
        return policy, 200

    @required_acl('auth.policies.read')
    def get(self):
        order = request.args.get('order', 'name')
        direction = request.args.get('direction', 'asc')
        limit = request.args.get('limit')
        offset = request.args.get('offset')
        term = request.args.get('search')

        policy_manager = current_app.config['policy_manager']
        policies = policy_manager.list(term, order, direction, limit, offset)
        total = policy_manager.count(term)
        return {'items': policies, 'total': total}, 200


class Policy(ErrorCatchingResource):

    @required_acl('auth.policies.{policy_uuid}.read')
    def get(self, policy_uuid):
        policy_manager = current_app.config['policy_manager']
        policy = policy_manager.get(policy_uuid)
        return policy, 200

    @required_acl('auth.policies.{policy_uuid}.delete')
    def delete(self, policy_uuid):
        policy_manager = current_app.config['policy_manager']
        policy_manager.delete(policy_uuid)
        return '', 204

    @required_acl('auth.policies.{policy_uuid}.edit')
    def put(self, policy_uuid):
        data = request.get_json()
        policy_manager = current_app.config['policy_manager']
        policy = policy_manager.update(policy_uuid, data)
        return policy, 200


class PolicyTemplate(ErrorCatchingResource):

    @required_acl('auth.policies.{policy_uuid}.edit')
    def delete(self, policy_uuid, template):
        policy_manager = current_app.config['policy_manager']
        policy_manager.delete_acl_template(policy_uuid, template)
        return '', 204

    @required_acl('auth.policies.{policy_uuid}.edit')
    def put(self, policy_uuid, template):
        policy_manager = current_app.config['policy_manager']
        policy_manager.add_acl_template(policy_uuid, template)
        return '', 204


class TokenRequestSchema(Schema):
    backend = fields.String(required=True)
    expiration = fields.Integer(validate=Range(min=1))


class Tokens(ErrorCatchingResource):

    def post(self):
        if request.authorization:
            login = request.authorization.username
            password = request.authorization.password
        else:
            login = ''
            password = ''

        args, error = TokenRequestSchema().load(request.get_json(force=True))
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


class UserRequestSchema(Schema):

    username = xfields.String(validate=validate.Length(min=1), required=True)
    password = xfields.String(validate=validate.Length(min=1), required=True)
    email_address = xfields.Email(required=True)

    @pre_load
    def dont_ignore_none(self, body):
        if body is None:
            return {}


class UserParamException(APIException):

    def __init__(self, message, details=None):
        super(UserParamException, self).__init__(400, message, 'invalid_data', details, 'users')

    @classmethod
    def from_errors(cls, errors):
        for field, infos in errors.iteritems():
            if not isinstance(infos, list):
                infos = [infos]
            for info in infos:
                return cls(info['message'], {field: info})


class Users(ErrorCatchingResource):

    def post(self):
        user_service = current_app.config['user_service']
        args, errors = UserRequestSchema().load(request.get_json(force=True))
        if errors:
            raise UserParamException.from_errors(errors)
        result = user_service.new_user(**args)
        return result, 200


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


# TODO: remove the =None on the user_service
def new_app(config, backends, policy_manager, token_manager, user_service=None):
    cors_config = dict(config['rest_api']['cors'])
    cors_enabled = cors_config.pop('enabled')
    app = Flask('wazo-auth')
    http_helpers.add_logger(app, logger)
    api = Api(app, prefix='/0.1')
    api.add_resource(Policies, '/policies')
    api.add_resource(Policy, '/policies/<string:policy_uuid>')
    api.add_resource(PolicyTemplate, '/policies/<string:policy_uuid>/acl_templates/<template>')
    api.add_resource(Tokens, '/token')
    api.add_resource(Token, '/token/<string:token>')
    api.add_resource(Users, '/users')
    api.add_resource(Backends, '/backends')
    api.add_resource(Swagger, '/api/api.yml')
    app.config.update(config)
    if cors_enabled:
        CORS(app, **cors_config)

    app.config['policy_manager'] = policy_manager
    app.config['token_manager'] = token_manager
    app.config['backends'] = backends
    app.config['user_service'] = user_service
    app.after_request(http_helpers.log_request)

    return app
