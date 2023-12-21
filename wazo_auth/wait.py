# Copyright 2020-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import socket
import sys
import time
from contextlib import closing

from xivo.chain_map import ChainMap
from xivo.config_helper import read_config_file_hierarchy

from wazo_auth.config import _DEFAULT_CONFIG

HOST = 'localhost'
TIMEOUT = 60
INTERVAL = 1


def iterations(timeout, interval):
    end_time = time.time() + timeout
    while time.time() < end_time:
        yield
        time_left = end_time - time.time()
        delay = time_left % interval
        time.sleep(delay)


def tcp_port_is_open(host, port):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(INTERVAL)
        return sock.connect_ex((host, port)) == 0


def get_wazo_auth_port():
    file_config = read_config_file_hierarchy(_DEFAULT_CONFIG)
    config = ChainMap(file_config, _DEFAULT_CONFIG)

    return config['rest_api']['port']


def main():
    port = get_wazo_auth_port()

    for _ in iterations(TIMEOUT, INTERVAL):
        if tcp_port_is_open(HOST, port):
            exit(0)
    else:
        print(f'Could not connect to wazo-auth on {HOST}:{port}', file=sys.stderr)
        exit(1)


if __name__ == '__main__':
    main()
