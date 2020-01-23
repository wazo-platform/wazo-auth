# Copyright 2016-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import requests

from wazo_auth.http_server import VERSION


# this function is not executed from the main thread
def self_check(config):
    port = config["rest_api"]["port"]
    scheme = "http"
    if config["rest_api"]["certificate"] and config["rest_api"]["private_key"]:
        scheme = "https"

    url = "{}://{}:{}/{}/backends".format(scheme, "localhost", port, VERSION)
    try:
        return (
            requests.get(
                url, headers={'accept': 'application/json'}, verify=False
            ).status_code
            == 200
        )
    except Exception:
        return False
