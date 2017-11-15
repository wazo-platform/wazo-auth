# -*- coding: utf-8 -*-
# Copyright (C) 2016 Avencall
#
# SPDX-License-Identifier: GPL-3.0+

import requests


# this function is not executed from the main thread
def self_check(port, certificate):
    url = 'https://localhost:{}/0.1/backends'.format(port)
    try:
        return requests.get(url, headers={'accept': 'application/json'}, verify=certificate).status_code == 200
    except Exception:
        return False
