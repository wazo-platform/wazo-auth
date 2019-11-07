# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import os
import random
import string
import tempfile
import traceback
import sys
from xivo.config_helper import parse_config_file, read_config_file_hierarchy

from wazo_auth import services
from wazo_auth.database import queries
from wazo_auth.database.helpers import init_db

from pwd import getpwnam

DEFAULT_WAZO_AUTH_CONFIG_FILE = '/etc/wazo-auth/config.yml'

CLI_CONFIG_DIR = '/root/.config/wazo-auth-cli'
CLI_CONFIG_FILENAME = os.path.join(CLI_CONFIG_DIR, '050-credentials.yml')
CLI_CONFIG = '''\
auth:
  username: {}
  password: {}
  backend: wazo_user
'''

VALID_CHARS = string.digits + string.ascii_lowercase + string.ascii_uppercase
USER = 'wazo-auth'
USERNAME = 'wazo-auth-cli'
PURPOSE = 'internal'
DEFAULT_POLICY_NAME = 'wazo_default_master_user_policy'

ERROR_MSG = '''\
Failed to bootstrap wazo-auth. Error is logged at {log_file}.
'''


def save_exception_and_exit():
    with tempfile.NamedTemporaryFile(
        mode='w', prefix='wazo-auth-bootstrap-', delete=False
    ) as log_file:
        traceback.print_exc(file=log_file)
        print(ERROR_MSG.format(log_file=log_file.name), file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Initialize wazo-auth')
    subparser = parser.add_subparsers(help='The action to execute', dest='action')
    subparser.add_parser('setup', help="deprecated")
    subparser.add_parser('complete')
    initial_user_parser = subparser.add_parser('initial-user')
    initial_user_parser.add_argument(
        "--uri", default=os.getenv("WAZO_AUTH_BOOTSTRAP_URI")
    )
    initial_user_parser.add_argument(
        "--username", default=os.getenv("WAZO_AUTH_BOOTSTRAP_USERNAME", USERNAME)
    )
    initial_user_parser.add_argument(
        "--password",
        default=os.getenv("WAZO_AUTH_BOOTSTRAP_PASSWORD", random_string(28)),
    )
    initial_user_parser.add_argument(
        "--policy-name",
        default=os.getenv("WAZO_AUTH_BOOTSTRAP_POLICY_NAME", DEFAULT_POLICY_NAME),
    )

    args = parser.parse_args()

    if args.action == 'setup':
        print("`wazo-auth-initial_user setup` command is no longer needed")
    elif args.action == 'complete':
        try:
            complete()
        except Exception:
            save_exception_and_exit()
    elif args.action == 'initial-user':
        uri = args.uri or get_database_uri_from_config()
        try:
            create_initial_user(uri, args.username, args.password, args.policy_name)
        except Exception:
            save_exception_and_exit()
    else:
        parser.print_help()


def get_database_uri_from_config():
    wazo_auth_config = read_config_file_hierarchy(
        {'config_file': DEFAULT_WAZO_AUTH_CONFIG_FILE}
    )
    return wazo_auth_config["db_uri"]


def create_initial_user(db_uri, username, password, purpose, policy_name):
    init_db(db_uri)
    dao = queries.DAO.from_defaults()
    tenant_tree = services.helpers.CachedTenantTree(dao.tenant)
    policy_service = services.PolicyService(dao, tenant_tree)
    user_service = services.UserService(dao, tenant_tree)
    if user_service.verify_password(username, password):
        # Already bootstrapped, just skip
        return
    else:
        users = user_service.list_users(username=username)
        if users:
            raise Exception(
                "User {} already exists with different credential".format(username)
            )
        else:
            user = user_service.new_user(
                enabled=True, username=username, password=password, purpose=purpose
            )
            policy_uuid = policy_service.list(name=policy_name)[0]['uuid']
            user_service.add_policy(user['uuid'], policy_uuid)


def complete():
    database_uri = get_database_uri_from_config()

    if os.path.exists(CLI_CONFIG_FILENAME):
        # NOTE(sileht): Allow custom username/password or reuse previous one
        wazo_auth_cli_config = parse_config_file(CLI_CONFIG_FILENAME)
        create_initial_user(
            database_uri,
            wazo_auth_cli_config["auth"]["username"],
            wazo_auth_cli_config["auth"]["password"],
            PURPOSE,
            DEFAULT_POLICY_NAME,
        )
    else:
        password = random_string(28)
        create_initial_user(
            database_uri, USERNAME, password, PURPOSE, DEFAULT_POLICY_NAME
        )

        try:
            os.makedirs(CLI_CONFIG_DIR)
        except FileExistsError:
            pass

        cli_config = CLI_CONFIG.format(USERNAME, password)
        write_private_file(CLI_CONFIG_FILENAME, USER, cli_config)


def write_private_file(filename, username, content):
    try:
        user = getpwnam(username)
        uid = user.pw_uid
        gid = user.pw_gid
    except KeyError:
        raise Exception('Unknown user {user}'.format(user=username))

    try:
        os.unlink(filename)
    except OSError:
        pass

    os.mknod(filename)
    os.chown(filename, uid, gid)
    with open(filename, 'w') as f:
        f.write(content)


def random_string(length):
    return ''.join(random.SystemRandom().choice(VALID_CHARS) for _ in range(length))
