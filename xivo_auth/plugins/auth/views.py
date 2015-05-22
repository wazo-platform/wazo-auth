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

import json
import hashlib

from datetime import datetime, timedelta

from tasks import clean_token
from flask import Blueprint, jsonify, current_app, request, make_response
from xivo_auth.extensions import httpauth, consul, celery, auth_token

auth = Blueprint('auth', __name__, template_folder='templates')


def _new_user_token_rule(uuid):
    rules = {'key': {'': {'policy': 'deny'},
                     'xivo/private/{uuid}'.format(uuid=uuid): {'policy': 'write'}}}
    return json.dumps(rules)


@auth.route("/0.1/token", methods=['POST'])
@httpauth.login_required
def authenticate():
    backend = [request.get_json()['type']]
    uuid = current_app.config['backends'].map_method(backend, 'get_uuid', httpauth.username())[0]
    token = create_token(uuid)
    seconds = 120
    task_id = hashlib.sha256('{token}'.format(token=token)).hexdigest()
    clean_token.apply_async(args=[token], countdown=seconds, task_id=task_id)
    now = datetime.now()
    expire = datetime.now() + timedelta(seconds=seconds)
    data = {'data': {'token': token,
                     'uuid': uuid,
                     'issued_at': now.isoformat(),
                     'expires_at': expire.isoformat()}}
    c = current_app._get_current_object()
    print auth_token.send(c, data=data)
    return jsonify(data)


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
    try:
        backend_names = [request.get_json()['type']]
        results = current_app.config['backends'].map_method(backend_names, 'verify_password', login, passwd)
        return results[0]
    except Exception:
        return False


def create_token(uuid):
    rules = _new_user_token_rule(uuid)
    return consul.acl.create(rules=rules)
