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
import os

from flask import Flask
from xivo.chain_map import ChainMap
from xivo.config_helper import read_config_file_hierarchy

from consul import Consul
from xivo.daemonize import pidfile_context
from xivo.xivo_logging import setup_logging
from xivo.xivo_logging import get_log_level_by_name
from xivo_auth import extensions
from xivo_auth import http
from xivo_auth.core import plugin_manager
from xivo_auth.core.celery_interface import make_celery, CeleryInterface
from xivo_auth import successful_auth_signal, token_removal_signal, get_token_data_signal
from flask.ext.cors import CORS
from pwd import getpwnam

logger = logging.getLogger(__name__)

TWO_HOURS = 60 * 60 * 2
_DEFAULT_CONFIG = {
    'user': 'www-data',
    'config_file': '/etc/xivo-auth/config.yml',
    'extra_config_files': '/etc/xivo-auth/conf.d',
    'log_level': 'info',
    'log_filename': '/var/log/xivo-auth.log',
    'pid_filename': '/var/run/xivo-auth/xivo-auth.pid',
    'default_token_lifetime': TWO_HOURS,
}


def _parse_cli_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config-file', action='store', help='The path to the config file')
    parser.add_argument('-u', '--user', help='User to run the daemon')
    parser.add_argument('-d', '--debug', action='store_true', help='Log debug messages')
    parser.add_argument('-f', '--foreground', action='store_true', help="Foreground, don't daemonize")
    parser.add_argument('-l',
                        '--log-level',
                        action='store',
                        help="Logs messages with LOG_LEVEL details. Must be one of:\n"
                             "critical, error, warning, info, debug. Default: %(default)s")
    parsed_args = parser.parse_args(argv)

    result = {}
    if parsed_args.config_file:
        result['config_file'] = parsed_args.config_file
    if parsed_args.user:
        result['user'] = parsed_args.user
    if parsed_args.debug:
        result['debug'] = parsed_args.debug
    if parsed_args.foreground:
        result['foreground'] = parsed_args.foreground
    if parsed_args.log_level:
        result['log_level'] = parsed_args.log_level

    return result


def _get_reinterpreted_raw_values(config):
    result = {}

    log_level = config.get('log_level')
    if log_level:
        result['log_level'] = get_log_level_by_name(log_level)

    return result


def _get_config():
    cli_config = _parse_cli_args(sys.argv[1:])
    file_config = read_config_file_hierarchy(ChainMap(cli_config, _DEFAULT_CONFIG))
    reinterpreted_config = _get_reinterpreted_raw_values(ChainMap(cli_config, file_config, _DEFAULT_CONFIG))
    return ChainMap(reinterpreted_config, cli_config, file_config, _DEFAULT_CONFIG)


class _Controller(object):

    def __init__(self, config):
        try:
            self._listen_addr = config['rest_api']['listen']
            self._listen_port = config['rest_api']['port']
            self._foreground = config['foreground']
        except KeyError:
            logger.error('Missing configuration to start the HTTP application')

        self._app = Flask(__name__)
        self._app.config.update(config)

        load_cors(self._app, config['rest_api'])

        extensions.celery = make_celery(self._app)
        extensions.consul = Consul(host=config['consul']['host'],
                                   port=config['consul']['port'],
                                   token=config['consul']['token'])

        register_signal_handlers(self._app)

        backends = plugin_manager.load_plugins(self._app, config)
        self._app.config['backends'] = backends
        self._app.register_blueprint(http.auth)

        sys.argv = [sys.argv[0]]  # For the celery process
        self._celery_iface = CeleryInterface(extensions.celery)
        self._celery_iface.daemon = not self._foreground
        self._celery_iface.start()

    def run(self):
        self._app.run(self._listen_addr, self._listen_port)
        if self._foreground:
            self._celery_iface.join()


def main():
    config = _get_config()

    setup_logging(config['log_filename'], config['foreground'], config['debug'], config['log_level'])

    user = config.get('user')
    if user:
        change_user(user)

    controller = _Controller(config)
    with pidfile_context(config['pid_filename'], config['foreground']):
        controller.run()


def register_signal_handlers(application):
    from xivo_auth.events import on_auth_success, remove_token, fetch_token_data
    get_token_data_signal.connect(fetch_token_data, application)
    successful_auth_signal.connect(on_auth_success, application)
    token_removal_signal.connect(remove_token, application)


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
