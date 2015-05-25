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

import hashlib

from flask import Blueprint, jsonify, current_app, request
from xivo_auth.extensions import httpauth, consul, celery
from xivo_auth import successful_auth_signal

auth = Blueprint('auth', __name__, template_folder='templates')


@auth.route("/0.1/token", methods=['POST'])
@httpauth.login_required
def authenticate():
    backend = [request.get_json()['type']]
    uuid = current_app.config['backends'].map_method(backend, 'get_uuid', httpauth.username())[0]
    _, data = successful_auth_signal.send(current_app._get_current_object(), uuid=uuid)[0]
    return jsonify({'data': data})


@auth.route("/0.1/token/<token>", methods=['DELETE'])
def revoke_token(token):
    task_id = hashlib.sha256('{token}'.format(token=token)).hexdigest()
    celery.control.revoke(task_id)
    print "Removing token: %s" % token
    consul.acl.destroy(token)
    return jsonify({'data': {'message': 'success'}})


@auth.route("/0.1/status", methods=['GET'])
def status():
    return jsonify({'data': {'status': 'running'}})


@httpauth.verify_password
def verify_password(login, passwd):
    backend_names = [request.get_json()['type']]
    results = current_app.config['backends'].map_method(backend_names, 'verify_password', login, passwd)
    return results[0] if results else False
