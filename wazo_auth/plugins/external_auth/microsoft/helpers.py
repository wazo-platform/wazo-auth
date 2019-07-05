# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time
from datetime import datetime, timedelta


def get_timestamp_expiration(expires_in):
    token_expiration_date = datetime.now() + timedelta(seconds=expires_in)
    return time.mktime(token_expiration_date.timetuple())
