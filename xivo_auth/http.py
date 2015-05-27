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

from datetime import datetime

from flask import Blueprint, jsonify, current_app, request, make_response
from xivo_auth.extensions import httpauth
from xivo_auth import successful_auth_signal, token_removal_signal, get_token_data_signal

auth = Blueprint('auth', __name__, template_folder='templates')

THE_PAST = '2000-01-01'


@auth.route("/0.1/token", methods=['POST'])
@httpauth.login_required
def authenticate():
    uuid = _call_backend('get_uuid', httpauth.username())
    data = _first_signal_result(successful_auth_signal, uuid=uuid)
    return jsonify({'data': data})


@auth.route("/0.1/token/<token>", methods=['DELETE'])
def revoke_token(token):
    data = _first_signal_result(token_removal_signal, token=token)
    return jsonify({'data': data})


@auth.route("/0.1/token/<token>", methods=['HEAD', 'GET'])
def check_token(token):
    try:
        token_data = _get_token_data(token)
        if token_data.get('expires_at', THE_PAST) > datetime.now().isoformat():
            if request.method == 'HEAD':
                return make_response('', 204)
            else:
                return jsonify({'data': token_data})
    except LookupError:
        'fallthrough'

    return make_response('', 403)


@auth.route('/0.1/backends', methods=['GET'])
def enabled_backends():
    return jsonify({'data': current_app.config['enabled_plugins']})


@httpauth.verify_password
def verify_password(login, passwd):
    try:
        return _call_backend('verify_password', login, passwd)
    except IndexError:
        return False


def _get_token_data(token):
    return _first_signal_result(get_token_data_signal, token=token)


def _first_signal_result(signal, **kwargs):
    _, data = signal.send(current_app._get_current_object(), **kwargs)[0]
    return data


def _call_backend(fn, *args, **kwargs):
    backend_names = [request.get_json(force=True)['type']]
    results = current_app.config['backends'].map_method(backend_names, fn, *args, **kwargs)
    return results[0]
