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
import logging

from datetime import datetime, timedelta
from extensions import celery, consul
from xivo_auth.helpers import values_to_dict

logger = logging.getLogger(__name__)


def remove_token(app, **extra):
    token = extra['token']
    task_id = hashlib.sha256('{token}'.format(token=token)).hexdigest()
    celery.control.revoke(task_id)
    _clean_consul_data(token)
    return {'message': 'success'}


def on_auth_success(app, **extra):
    uuid = extra['uuid']
    logger.debug('Authentication succesfull for %s', uuid)
    token = create_token(uuid)
    if 'expiration' in extra:
        seconds = extra['expiration']
    else:
        seconds = app.config['default_token_lifetime']
    task_id = hashlib.sha256('{token}'.format(token=token)).hexdigest()
    _clean_token.apply_async(args=[token], countdown=seconds, task_id=task_id)
    now = datetime.now()
    expire = datetime.now() + timedelta(seconds=seconds)
    token_data = {'token': token,
                  'uuid': uuid,
                  'issued_at': now.isoformat(),
                  'expires_at': expire.isoformat()}
    _add_token_data(token, token_data)
    return token_data


def _new_user_token_rule(uuid):
    rules = {'key': {'': {'policy': 'deny'},
                     'xivo/private/{uuid}'.format(uuid=uuid): {'policy': 'write'}}}
    return json.dumps(rules)


def create_token(uuid):
    rules = _new_user_token_rule(uuid)
    return consul.acl.create(rules=rules)


def fetch_token_data(app, token, **extra):
    key = 'xivo/xivo-auth/tokens/{}'.format(token)
    index, values = consul.kv.get(key, recurse=True)
    if not values:
        raise LookupError('No such token {}'.format(token))

    return values_to_dict(values)['xivo']['xivo-auth']['tokens'][token]


def _add_token_data(token, token_data):
    key_tpl = 'xivo/xivo-auth/tokens/{token}/{key}'
    for key, value in token_data.iteritems():
        complete_key = key_tpl.format(token=token, key=key)
        consul.kv.put(complete_key, value)


def _clean_consul_data(token):
    logger.debug("Removing token: %s", token)
    consul.acl.destroy(token)
    consul.kv.delete('xivo/xivo-auth/tokens/{}'.format(token), recurse=True)


@celery.task()
def _clean_token(token):
    _clean_consul_data(token)
    return json.dumps({'data': 'Token cleaned...'})
