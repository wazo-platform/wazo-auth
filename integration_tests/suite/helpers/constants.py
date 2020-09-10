# Copyright 2019-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import os

UNKNOWN_UUID = '00000000-0000-0000-0000-000000000000'
UNKNOWN_TENANT = '55ee61f3-c4a5-427c-9f40-9d5c33466240'
DB_URI = os.getenv('DB_URI', 'postgresql://asterisk:proformatique@localhost:{port}')
NB_DEFAULT_GROUPS = 1
