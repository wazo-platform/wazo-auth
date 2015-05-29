# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Avencall
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

from flask import Blueprint, jsonify, current_app, request, make_response
from xivo_auth.extensions import httpauth

auth = Blueprint('auth', __name__, template_folder='templates')

THE_PAST = '2000-01-01'


@auth.route("/0.1/token", methods=['POST'])
@httpauth.login_required
def authenticate():
    data = request.get_json()
    args = {}
    if 'expiration' in data:
        if not data['expiration'] > 0:
            return make_response('Invalid expiration', 400)

        args['expiration'] = data['expiration']

    uuid = _call_backend('get_uuid', httpauth.username())
    token = current_app.token_manager.new_token(uuid, **args)
    return jsonify({'data': token.to_dict()})


@auth.route("/0.1/token/<token>", methods=['DELETE'])
def revoke_token(token):
    current_app.token_manager.remove_token(token)
    return jsonify({'data': {'message': 'success'}})


@auth.route("/0.1/token/<token>", methods=['HEAD', 'GET'])
def check_token(token):
    try:
        token = current_app.token_manager.get(token)
        if not token.is_expired():
            if request.method == 'HEAD':
                return make_response('', 204)
            else:
                return jsonify({'data': token.to_dict()})
    except LookupError:
        'fallthrough'

    return make_response('', 404)


@auth.route('/0.1/backends', methods=['GET'])
def enabled_backends():
    return jsonify({'data': current_app.config['enabled_plugins']})


@httpauth.verify_password
def verify_password(login, passwd):
    try:
        return _call_backend('verify_password', login, passwd)
    except IndexError:
        return False


def _call_backend(fn, *args, **kwargs):
    backend_names = [request.get_json()['backend']]
    results = current_app.config['backends'].map_method(backend_names, fn, *args, **kwargs)
    return results[0]
