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
from xivo.config_helper import parse_config_dir, read_config_file_hierarchy
from xivo.xivo_logging import get_log_level_by_name


TWO_HOURS = 60 * 60 * 2
_DEFAULT_CONFIG = {
    'user': 'www-data',
    'config_file': '/etc/xivo-auth/config.yml',
    'service_config_dir': '/etc/xivo-auth/services.d',
    'extra_config_files': '/etc/xivo-auth/conf.d',
    'log_level': 'info',
    'log_filename': '/var/log/xivo-auth.log',
    'pid_filename': '/var/run/xivo-auth/xivo-auth.pid',
    'default_token_lifetime': TWO_HOURS,
    'rest_api': {'cors': {'enabled': False},
                 'certificate': '/usr/share/xivo-certs/server.crt',
                 'private_key': '/usr/share/xivo-certs/server.key'},
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


def _load_service_config_dir(config):
    service_config_dir = config.get('service_config_dir')
    if not service_config_dir:
        return {}

    service_configs = parse_config_dir(service_config_dir)
    services = {}
    for service_config in service_configs:
        service_name = service_config.get('name')
        if not service_name:
            continue
        services[service_name] = service_config

    return {'services': services}


def get_config(argv):
    cli_config = _parse_cli_args(argv)
    file_config = read_config_file_hierarchy(ChainMap(cli_config, _DEFAULT_CONFIG))
    reinterpreted_config = _get_reinterpreted_raw_values(ChainMap(cli_config, file_config, _DEFAULT_CONFIG))
    service_dir_configuration = _load_service_config_dir(ChainMap(cli_config, file_config, _DEFAULT_CONFIG))
    return ChainMap(reinterpreted_config, service_dir_configuration,  cli_config, file_config, _DEFAULT_CONFIG)
