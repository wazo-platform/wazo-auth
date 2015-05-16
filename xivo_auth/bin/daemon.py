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
import logging
import sys

from xivo.chain_map import ChainMap
from xivo.config_helper import read_config_file_hierarchy

from consul import Consul
from xivo_auth import extensions
from xivo_auth.main import create_app
from xivo_auth.core import plugin_manager
from xivo_auth.core.celery_interface import make_celery, CeleryInterface
from flask.ext.cors import CORS
from pwd import getpwnam
import os

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


def main():
    config = _get_config()
    user = config['user']

    if user:
        change_user(user)

    application = create_app()
    application.config.update(config)
    load_cors(application, config['general'])
    extensions.celery = make_celery(application)
    extensions.consul = Consul(host=config['consul']['host'],
                               port=config['consul']['port'],
                               token=config['consul']['token'])

    plugin_manager.load_plugins(application)

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
