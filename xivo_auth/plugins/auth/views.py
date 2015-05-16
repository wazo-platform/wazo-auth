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
from datetime import datetime, timedelta

from flask import Blueprint, jsonify
from xivo_dao import user_dao
from xivo_auth.extensions import httpauth, consul
from tasks import clean_token

auth = Blueprint('auth', __name__, template_folder='templates')


def _new_user_token_rule(uuid):
    rules = {'key': {'': {'policy': 'deny'},
                     'xivo/private/{uuid}'.format(uuid=uuid): {'policy': 'write'}}}
    return json.dumps(rules)


@auth.route("/0.1/auth/tokens", methods=['POST'])
@httpauth.login_required
def authenticate():
    uuid = user_dao.get_uuid_by_username(httpauth.username())
    token = create_token(uuid)
    seconds = 120
    clean_token.apply_async(args=[token], countdown=seconds)
    now = datetime.now()
    expire = datetime.now() + timedelta(seconds=seconds)
    return jsonify({'data': {'token': token,
                             'uuid': uuid,
                             'issued_at': now.isoformat(),
                             'expires_at': expire.isoformat()}})


@httpauth.verify_password
def verify_password(login, passwd):
    return user_dao.check_username_password(login, passwd)


def create_token(uuid):
    rules = _new_user_token_rule(uuid)
    return consul.acl.create(rules=rules)
