# Copyright 2019-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import os

UNKNOWN_UUID = '00000000-0000-0000-0000-000000000000'
UNKNOWN_SLUG = 'UNKNOWN-SLUG'
UNKNOWN_TENANT = '55ee61f3-c4a5-427c-9f40-9d5c33466240'
DB_URI = os.getenv('DB_URI', 'postgresql://asterisk:proformatique@127.0.0.1:{port}')
ISO_DATETIME = '%Y-%m-%dT%H:%M:%S.%f'
NB_DEFAULT_GROUPS = 2
NB_DEFAULT_GROUPS_NOT_READONLY = 1
ALL_USERS_POLICY_SLUG = 'wazo-all-users-policy'
DEFAULT_POLICIES_SLUG = [
    ALL_USERS_POLICY_SLUG,
    'wazo_default_admin_policy',
    'wazo_default_user_policy',
]
NB_DEFAULT_POLICIES = len(DEFAULT_POLICIES_SLUG)
