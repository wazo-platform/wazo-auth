# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Avencall
# Copyright (C) 2016 Proformatique, Inc.
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

import time
import logging
import os

from flask import current_app, request, make_response
from flask_restful import Resource
from pkg_resources import resource_string

from xivo_auth.token import ManagerException

logger = logging.getLogger(__name__)

XIVO_UUID = os.getenv('XIVO_UUID')


def _error(code, msg):
    return {'reason': [msg],
            'timestamp': [time.time()],
            'status_code': code}, code


def _is_positive_integer(i):
    return isinstance(i, int) and i > 0


class Tokens(Resource):

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

        try:
            token = current_app.config['token_manager'].new_token(backend, login, args)
        except ManagerException as e:
            return _error(e.code, str(e))

        data = token.to_dict()
        data['xivo_uuid'] = XIVO_UUID
        response = {'data': data}
        return response, 200


class Token(Resource):

    def delete(self, token):
        try:
            current_app.config['token_manager'].remove_token(token)
        except ManagerException as e:
            return _error(e.code, str(e))

        return {'data': {'message': 'success'}}

    def get(self, token):
        required_acl = request.args.get('scope')
        try:
            token = current_app.config['token_manager'].get(token, required_acl)
            data = token.to_dict()
            data['xivo_uuid'] = XIVO_UUID
            return {'data': data}
        except ManagerException as e:
            return _error(e.code, str(e))

    def head(self, token):
        required_acl = request.args.get('scope')
        try:
            token = current_app.config['token_manager'].get(token, required_acl)
            return '', 204
        except ManagerException as e:
            return _error(e.code, str(e))


class Backends(Resource):

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
