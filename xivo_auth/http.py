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

from flask import current_app, request, make_response
from flask_restful import Resource
from pkg_resources import resource_string

from xivo_auth.exceptions import ManagerException

logger = logging.getLogger(__name__)


def _error(code, msg):
    return {'reason': [msg],
            'timestamp': [time.time()],
            'status_code': code}, code


def _is_positive_integer(i):
    return isinstance(i, int) and i > 0


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
    method_decorators = [handle_manager_exception] + Resource.method_decorators


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


class Tokens(ErrorCatchingResource):

    def post(self):
        if request.authorization:
            login = request.authorization.username
            password = request.authorization.password
        else:
            login = ''
            password = ''
        args = {}

        if not verify_password(login, password, args):
            return _error(401, 'Authentication Failed')

        data = request.get_json()
        expiration = data.get('expiration')
        if expiration is not None:
            if _is_positive_integer(expiration):
                args['expiration'] = expiration
            else:
                return _error(400, 'Invalid expiration')

        backend_name = request.get_json()['backend']
        backend = current_app.config['backends'][backend_name].obj

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


class Api(Resource):

    api_package = "xivo_auth.swagger"
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


def verify_password(login, passwd, args):
    try:
        return _call_backend('verify_password', login, passwd, args)
    except IndexError:
        return False


def _call_backend(fn, *args, **kwargs):
    backend_names = [request.get_json()['backend']]
    results = current_app.config['backends'].map_method(backend_names, fn, *args, **kwargs)
    return results[0]
