# Copyright 2019-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import os

UNKNOWN_UUID = '00000000-0000-0000-0000-000000000000'
DB_URI = os.getenv('DB_URI', 'postgresql://asterisk:proformatique@localhost:{port}')
NB_DEFAULT_GROUPS = 1
