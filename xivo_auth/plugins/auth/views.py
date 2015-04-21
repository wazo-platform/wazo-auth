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

from sqlalchemy import and_
from flask import Blueprint, jsonify, request
from xivo_auth.extensions import sqlalchemy as db
from xivo_dao import user_dao
from xivo_dao.alchemy.userfeatures import UserFeatures
from xivo_auth.extensions import httpauth
from tasks import clean_token
from factory import consul

auth = Blueprint('auth', __name__, template_folder='templates')


def _new_user_token_rule(uuid):
    rules = {'key': {'': {'policy': 'deny'},
                     'xivo/private/{uuid}'.format(uuid=uuid): {'policy': 'write'}}}
    return json.dumps(rules)


@auth.route("/api/user")
@httpauth.login_required
def authenticate():
    data = json.loads(request.data)
    uuid = user_dao.get_uuid_by_username_password(data['login'], data['passwd'])
    print 'uuid', uuid
    token = create_token(uuid)
    task = clean_token.apply_async(args=[token], countdown=5)
    return jsonify({'data': {'task': task.id, 'token': token}})


@httpauth.verify_password
def verify_password(login, passwd):
    rows = db.session.query(UserFeatures).filter(
        and_(UserFeatures.loginclient == login,
             UserFeatures.passwdclient == passwd))

    for row in rows.all():
        print row
        return True

    return False


def create_token(uuid):
    rules = _new_user_token_rule(uuid)
    return consul.acl.create(rules=rules)
