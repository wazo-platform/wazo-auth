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

import argparse
import hashlib
import json
import logging
import sys
import os

from datetime import datetime, timedelta

from xivo.chain_map import ChainMap
from xivo.config_helper import read_config_file_hierarchy

from consul import Consul
from xivo_auth import extensions
from xivo_auth.main import create_app
from xivo_auth.core import plugin_manager
from xivo_auth.core.celery_interface import make_celery, CeleryInterface
from xivo_auth import successful_auth_signal
from flask.ext.cors import CORS
from pwd import getpwnam

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG = {
    'user': 'www-data',
    'config_file': '/etc/xivo-auth/config.yml',
    'extra_config_files': '/etc/xivo-auth/conf.d',
}


def _parse_cli_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config-file', action='store', help='The path to the config file')
    parser.add_argument('-u', '--user', help='User to run the daemon')
    parsed_args = parser.parse_args(argv)

    result = {}
    if parsed_args.config_file:
        result['config_file'] = parsed_args.config_file
    if parsed_args.user:
        result['user'] = parsed_args.user

    return result


def _get_config():
    cli_config = _parse_cli_args(sys.argv[1:])
    file_config = read_config_file_hierarchy(ChainMap(cli_config, _DEFAULT_CONFIG))
    return ChainMap(cli_config, file_config, _DEFAULT_CONFIG)


def remove_token(app, data, **extra):
    print 'In the handler'
    return 'lol'


def _new_user_token_rule(uuid):
    rules = {'key': {'': {'policy': 'deny'},
                     'xivo/private/{uuid}'.format(uuid=uuid): {'policy': 'write'}}}
    return json.dumps(rules)


def create_token(uuid):
    rules = _new_user_token_rule(uuid)
    return extensions.consul.acl.create(rules=rules)


def _on_auth_success(app, **extra):
    from xivo_auth import tasks
    uuid = extra['uuid']
    print 'Auth success ', uuid
    token = create_token(uuid)
    seconds = 120
    task_id = hashlib.sha256('{token}'.format(token=token)).hexdigest()
    tasks.clean_token.apply_async(args=[token], countdown=seconds, task_id=task_id)
    now = datetime.now()
    expire = datetime.now() + timedelta(seconds=seconds)
    return {'token': token,
            'uuid': uuid,
            'issued_at': now.isoformat(),
            'expires_at': expire.isoformat()}


def main():
    config = _get_config()
    user = config['user']

    if user:
        change_user(user)

    application = create_app()
    application.config.update(config)

    load_cors(application, config['general'])
    successful_auth_signal.connect(_on_auth_success, application)
    extensions.celery = make_celery(application)
    extensions.consul = Consul(host=config['consul']['host'],
                               port=config['consul']['port'],
                               token=config['consul']['token'])

    backends = plugin_manager.load_plugins(application, config)
    application.config['backends'] = backends

    sys.argv = [sys.argv[0]]
    celery_interface = CeleryInterface(extensions.celery)
    celery_interface.start()

    application.run(config['general']['listen'],
                    config['general']['port'])

    celery_interface.join()


def change_user(user):
    try:
        uid = getpwnam(user).pw_uid
        gid = getpwnam(user).pw_gid
    except KeyError:
        raise Exception('Unknown user {user}'.format(user=user))

    try:
        os.setgid(gid)
        os.setuid(uid)
    except OSError as e:
        raise Exception('Could not change owner to user {user}: {error}'.format(user=user, error=e))


def load_cors(app, config):
    cors_config = dict(config.get('cors', {}))
    enabled = cors_config.pop('enabled', False)
    if enabled:
        CORS(app, **cors_config)


if __name__ == '__main__':
    main()
