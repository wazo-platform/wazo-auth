# Copyright 2015-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse

from xivo.chain_map import ChainMap
from xivo.config_helper import read_config_file_hierarchy_accumulating_list
from xivo.xivo_logging import get_log_level_by_name

TWO_HOURS = 60 * 60 * 2
_DEFAULT_HTTP_PORT = 9497
_DEFAULT_CONFIG = {
    'user': 'wazo-auth',
    'config_file': '/etc/wazo-auth/config.yml',
    'extra_config_files': '/etc/wazo-auth/conf.d',
    'update_policy_on_startup': True,
    'log_level': 'info',
    'log_filename': '/var/log/wazo-auth.log',
    'default_token_lifetime': TWO_HOURS,
    'token_cleanup_interval': 60.0,
    'password_reset_expiration': 172800,
    'password_reset_from_name': 'wazo-auth',
    'password_reset_from_address': 'noreply@wazo.community',
    'password_reset_email_template': '/var/lib/wazo-auth/templates/password_reset_email.jinja',
    'password_reset_email_subject_template': '/var/lib/wazo-auth/templates/password_reset_email_subject.jinja',  # noqa
    'email_confirmation_expiration': 172800,
    'email_confirmation_template': '/var/lib/wazo-auth/templates/email_confirmation.jinja',
    'email_confirmation_subject_template': '/var/lib/wazo-auth/templates/email_confirmation_subject.jinja',  # noqa
    'email_confirmation_from_name': 'wazo-auth',
    'email_confirmation_from_address': 'noreply@wazo.community',
    'email_confirmation_get_response_body_template': '/var/lib/wazo-auth/templates/email_confirmation_get_body.jinja',  # noqa
    'email_confirmation_get_mimetype': 'text/html',
    'oauth2_synchronization_ws_url_template': 'wss://oauth.wazo.io/ws/{state}',
    'oauth2_synchronization_redirect_url_template': 'https://oauth.wazo.io/{auth_type}/authorize',
    'enabled_http_plugins': {
        'api': True,
        'backends': True,
        'config': True,
        'email_confirm': True,
        'external': True,
        'group_policy': True,
        'groups': True,
        'ldap_config': True,
        'password_reset': True,
        'policies': True,
        'sessions': True,
        'status': True,
        'tenants': True,
        'tokens': True,
        'user_email': True,
        'user_group': True,
        'user_policy': True,
        'user_registration': False,
        'user_session': True,
        'users': True,
    },
    'enabled_backend_plugins': {
        'ldap_user': True,
        'wazo_user': True,
    },
    'enabled_metadata_plugins': {
        'default_user': True,
        'default_internal': True,
        'default_external_api': True,
    },
    'purpose_metadata_mapping': {'user': [], 'internal': [], 'external_api': []},
    'enabled_external_auth_plugins': {
        'google': True,
        'microsoft': True,
        'mobile': True,
    },
    'backend_policies': {},  # since 21.14: Deprecated
    'rest_api': {
        'max_threads': 25,
        'num_proxies': 1,
        'listen': '127.0.0.1',
        'port': _DEFAULT_HTTP_PORT,
        'certificate': None,  # Deprecated
        'private_key': None,  # Deprecated
        'cors': {
            'enabled': True,
            'allow_headers': [
                'Content-Type',
                'Authorization',
                'X-Auth-Token',
                'Wazo-Tenant',
                'Wazo-Session-Type',
            ],
        },
    },
    'consul': {
        'scheme': 'http',
        'port': 8500,
    },
    'service_discovery': {
        'enabled': False,
        'advertise_address': 'auto',
        'advertise_address_interface': 'eth0',
        'advertise_port': _DEFAULT_HTTP_PORT,
        'ttl_interval': 30,
        'refresh_interval': 27,
        'retry_interval': 2,
        'extra_tags': [],
    },
    'amqp': {
        'uri': 'amqp://guest:guest@localhost:5672/',
        'exchange_name': 'xivo',
        'exchange_type': 'topic',
    },
    'smtp': {'hostname': 'localhost', 'port': 25},
    'db_connect_retry_timeout_seconds': 300,
    'db_uri': 'postgresql://asterisk:proformatique@localhost/asterisk',
    'db_upgrade_on_startup': False,
    'confd_db_uri': 'postgresql://asterisk:proformatique@localhost/asterisk',
    'all_users_policies': {},
    'default_policies': {},
    'tenant_default_groups': {},
    'bootstrap_user_on_startup': False,
    'bootstrap_user_username': None,
    'bootstrap_user_password': None,
}


def _parse_cli_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-c', '--config-file', action='store', help='The path to the config file'
    )
    parser.add_argument('-u', '--user', help='User to run the daemon')
    parser.add_argument('-d', '--debug', action='store_true', help='Log debug messages')
    parser.add_argument(
        '-l',
        '--log-level',
        action='store',
        help="Logs messages with LOG_LEVEL details. Must be one of:\n"
        "critical, error, warning, info, debug. Default: %(default)s",
    )
    parser.add_argument(
        "--db-upgrade-on-startup",
        action="store_true",
        default=False,
        help="Upgrade database on startup if needed",
    )
    parser.add_argument(
        '--listen-port',
        action='store',
        help='Port on which the rest API will listen',
    )
    parser.add_argument(
        '--log-file',
        action='store',
        help='The log filename to log to',
    )
    parsed_args = parser.parse_args(argv)

    result = {}
    if parsed_args.listen_port:
        result['rest_api'] = {'listen': parsed_args.listen_port}
    if parsed_args.log_file:
        result['log_filename'] = parsed_args.log_file
    if parsed_args.config_file:
        result['config_file'] = parsed_args.config_file
    if parsed_args.user:
        result['user'] = parsed_args.user
    if parsed_args.debug:
        result['debug'] = parsed_args.debug
    if parsed_args.log_level:
        result['log_level'] = parsed_args.log_level
    if parsed_args.db_upgrade_on_startup:
        result['db_upgrade_on_startup'] = parsed_args.db_upgrade_on_startup

    return result


def _get_reinterpreted_raw_values(config):
    result = {}

    log_level = config.get('log_level')
    if log_level:
        result['log_level'] = get_log_level_by_name(log_level)

    return result


def get_config(argv):
    cli_config = _parse_cli_args(argv)
    file_config = read_config_file_hierarchy_accumulating_list(
        ChainMap(cli_config, _DEFAULT_CONFIG)
    )
    reinterpreted_config = _get_reinterpreted_raw_values(
        ChainMap(cli_config, file_config, _DEFAULT_CONFIG)
    )
    return ChainMap(reinterpreted_config, cli_config, file_config, _DEFAULT_CONFIG)
