# Copyright 2020-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from urllib import parse


def extract_connection_params(headers):
    result = {}

    parsed = parse.urlsplit(f'//{headers["Host"]}')
    if parsed.hostname:
        result['hostname'] = parsed.hostname
    if parsed.port:
        result['port'] = parsed.port

    prefix = headers.get('X-Script-Name')
    if prefix:
        result['prefix'] = prefix

    return result
