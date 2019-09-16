# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import json
import os
import random
import requests
import string
import tempfile
import time
import traceback
import sys
from xivo.config_helper import read_config_file_hierarchy

from pwd import getpwnam

KEY_LENGTH = 20
KEY_FILENAME = '/var/lib/wazo-auth/init.key'

DEFAULT_WAZO_AUTH_CONFIG_FILE = '/etc/wazo-auth/config.yml'

INIT_CONFIG_FILENAME = '/etc/wazo-auth/conf.d/050-init-config.yml'
INIT_CONFIG_FILE = '''\
init_key_filename: {}
enabled_http_plugins:
  init: true
'''

USER_CONFIG_DIR = '/root/.config'
CLI_CONFIG_DIR = os.path.join(USER_CONFIG_DIR, 'wazo-auth-cli')
CLI_CONFIG_FILENAME = os.path.join(CLI_CONFIG_DIR, '050-credentials.yml')
CLI_CONFIG = '''\
auth:
  username: {username}
  password: {password}
  backend: wazo_user
'''

VALID_CHARS = string.digits + string.ascii_lowercase + string.ascii_uppercase
USER = 'wazo-auth'
USERNAME = 'wazo-auth-cli'
PURPOSE = 'internal'
URL = 'https://localhost:{}/0.1/init'
HEADERS = {'Accept': 'application/json', 'Content-Type': 'application/json'}

ERROR_MSG = '''\
Failed to bootstrap wazo-auth. Error is logged at {log_file}.
Use the following command to bootstrap manually:
wazo-auth && sleep 5 && wazo-auth-bootstrap complete && killall wazo-auth
'''


def main():
    parser = argparse.ArgumentParser(description='Initialize wazo-auth')
    parser.add_argument('action', help='The action to execute (setup or complete)')
    args = parser.parse_args()

    if args.action == 'setup':
        setup()
    elif args.action == 'complete':
        try:
            complete()
        except Exception as e:
            with tempfile.NamedTemporaryFile(mode='w', prefix='wazo-auth-bootstrap-', delete=False) as log_file:
                traceback.print_exc(file=log_file)
                print(ERROR_MSG.format(log_file=log_file.name), file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()


def complete():
    if not os.path.exists(KEY_FILENAME):
        return

    with open(KEY_FILENAME, 'r') as f:
        for line in f:
            key = line.strip()
            break

    password = random_string(28)
    body = {
        'key': key,
        'username': USERNAME,
        'password': password,
        'purpose': PURPOSE,
    }

    wazo_auth_config = read_config_file_hierarchy({'config_file': DEFAULT_WAZO_AUTH_CONFIG_FILE})
    port = wazo_auth_config['rest_api']['https']['port']
    url = URL.format(port)
    for _ in range(40):
        try:
            response = requests.post(url, data=json.dumps(body), headers=HEADERS, verify=False)
            break
        except requests.exceptions.ConnectionError:
            time.sleep(0.25)
    else:
        raise Exception('failed to connect to wazo-auth')

    response.raise_for_status()

    for d in [USER_CONFIG_DIR, CLI_CONFIG_DIR]:
        try:
            os.mkdir(d)
        except OSError:
            pass  # Directory already exists

    cli_config = CLI_CONFIG.format(**body)
    write_private_file(CLI_CONFIG_FILENAME, USER, cli_config)

    try:
        os.remove(INIT_CONFIG_FILENAME)
    except OSError:
        pass  # Already deleted


def setup():
    key = random_string(KEY_LENGTH)
    content = INIT_CONFIG_FILE.format(KEY_FILENAME)

    with open(INIT_CONFIG_FILENAME, 'w') as f:
        f.write(content)

    if os.path.exists(KEY_FILENAME):
        return

    write_private_file(KEY_FILENAME, USER, key)


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
    return ''.join(random.SystemRandom().choice(VALID_CHARS) for _ in range(KEY_LENGTH))
