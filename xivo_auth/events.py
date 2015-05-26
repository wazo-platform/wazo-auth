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
from extensions import celery, consul


def remove_token(app, **extra):
    token = extra['token']
    task_id = hashlib.sha256('{token}'.format(token=token)).hexdigest()
    celery.control.revoke(task_id)
    print "Removing token: %s" % token
    consul.acl.destroy(token)
    return {'message': 'success'}


def on_auth_success(app, **extra):
    uuid = extra['uuid']
    print 'Auth success ', uuid
    token = create_token(uuid)
    seconds = 10
    task_id = hashlib.sha256('{token}'.format(token=token)).hexdigest()
    _clean_token.apply_async(args=[token], countdown=seconds, task_id=task_id)
    now = datetime.now()
    expire = datetime.now() + timedelta(seconds=seconds)
    return {'token': token,
            'uuid': uuid,
            'issued_at': now.isoformat(),
            'expires_at': expire.isoformat()}


def _new_user_token_rule(uuid):
    rules = {'key': {'': {'policy': 'deny'},
                     'xivo/private/{uuid}'.format(uuid=uuid): {'policy': 'write'}}}
    return json.dumps(rules)


def create_token(uuid):
    rules = _new_user_token_rule(uuid)
    return consul.acl.create(rules=rules)


@celery.task()
def _clean_token(token):
    print "Removing token: %s" % token
    consul.acl.destroy(token)
    return json.dumps({'data': 'Token cleaned...'})
