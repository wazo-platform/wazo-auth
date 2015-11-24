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

from xivo.chain_map import ChainMap
from xivo.http_helpers import DEFAULT_CIPHERS
from xivo.config_helper import (parse_config_file,
                                read_config_file_hierarchy)
from xivo.xivo_logging import get_log_level_by_name


TWO_HOURS = 60 * 60 * 2
_DEFAULT_CONFIG = {
    'user': 'www-data',
    'config_file': '/etc/xivo-auth/config.yml',
    'extra_config_files': '/etc/xivo-auth/conf.d',
    'log_level': 'info',
    'log_filename': '/var/log/xivo-auth.log',
    'pid_filename': '/var/run/xivo-auth/xivo-auth.pid',
    'default_token_lifetime': TWO_HOURS,
    'rest_api': {
        'https': {
            'listen': '0.0.0.0',
            'port': 9497,
            'certificate': '/usr/share/xivo-certs/server.crt',
            'private_key': '/usr/share/xivo-certs/server.key',
            'ciphers': DEFAULT_CIPHERS,
        },
        'cors': {
            'enabled': False,
        },
    },
    'consul': {
        'scheme': 'https',
        'host': 'localhost',
        'port': 8500,
        'verify': '/usr/share/xivo-certs/server.crt',
    },
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


def _load_key_files(config):
    key_configs = {'services': {}}
    for service_id, service_config in config.get('services', {}).iteritems():
        key_configs['services'][service_id] = {'service_key': _load_key_file(service_config)}
    return key_configs


def _load_key_file(service_config):
    key_file = parse_config_file(service_config['key_file'])
    return key_file['service_key']


def get_config(argv):
    cli_config = _parse_cli_args(argv)
    file_config = read_config_file_hierarchy(ChainMap(cli_config, _DEFAULT_CONFIG))
    reinterpreted_config = _get_reinterpreted_raw_values(ChainMap(cli_config, file_config, _DEFAULT_CONFIG))
    key_configs = _load_key_files(ChainMap(cli_config, file_config, _DEFAULT_CONFIG))
    return ChainMap(reinterpreted_config, key_configs, cli_config, file_config, _DEFAULT_CONFIG)
