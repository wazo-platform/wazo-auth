# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import argparse
import json
import os
import random
import requests
import string
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

CLI_CONFIG_DIR = '/root/.config/wazo-auth-cli'
CLI_CONFIG_FILENAME = os.path.join(CLI_CONFIG_DIR, '050-credentials.yml')
CLI_CONFIG = '''\
auth:
  username: {username}
  password: {password}
  backend: wazo_user
'''

VALID_CHARS = string.digits + string.lowercase + string.uppercase
USER = 'wazo-auth'
USERNAME = 'wazo-auth-cli'
URL = 'https://localhost:{}/0.1/init'
HEADERS = {'Accept': 'application/json', 'Content-Type': 'application/json'}


def main():
    parser = argparse.ArgumentParser(description='Initialize wazo-auth')
    parser.add_argument('action', help='The action to execute (setup or complete)')
    args = parser.parse_args()

    if args.action == 'setup':
        setup()
    elif args.action == 'complete':
        complete()
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
    body = dict(
        key=key,
        username=USERNAME,
        password=password,
    )

    wazo_auth_config = read_config_file_hierarchy({'config_file': DEFAULT_WAZO_AUTH_CONFIG_FILE})
    port = wazo_auth_config['rest_api']['https']['port']
    url = URL.format(port)
    response = requests.post(url, data=json.dumps(body), headers=HEADERS, verify=False)
    response.raise_for_status()

    try:
        os.mkdir(CLI_CONFIG_DIR)
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

    os.mknod(filename)
    os.chown(filename, uid, gid)
    with open(filename, 'a') as f:
        f.write(content)


def random_string(length):
    return ''.join(random.SystemRandom().choice(VALID_CHARS) for _ in range(KEY_LENGTH))
