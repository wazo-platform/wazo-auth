# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import random
import string
import os

from pwd import getpwnam

KEY_LENGTH = 20
KEY_FILENAME = '/var/lib/wazo-auth/init.key'
CONFIG_FILE = '''\
init_key_filename: {}
enabled_http_plugins:
  init: true
'''
VALID_CHARS = string.digits + string.lowercase + string.uppercase
USER = 'wazo-auth'


def main():
    try:
        user = getpwnam(USER)
        uid = user.pw_uid
        gid = user.pw_gid
    except KeyError:
        raise Exception('Unknown user {user}'.format(user=user))

    key = ''.join(random.SystemRandom().choice(VALID_CHARS) for _ in range(KEY_LENGTH))
    content = CONFIG_FILE.format(KEY_FILENAME)

    with open('/etc/wazo-auth/conf.d/050-init-config.yml', 'w') as f:
        f.write(content)

    if os.path.exists(KEY_FILENAME):
        return

    os.mknod(KEY_FILENAME)
    os.chown(KEY_FILENAME, uid, gid)
    with open(KEY_FILENAME, 'a') as f:
        f.write(key)
