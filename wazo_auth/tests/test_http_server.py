# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import socket

from ..http_server import ReusePortWSGIServer


def test_reuse_port_wsgi_server_sets_so_reuseport():
    sock = ReusePortWSGIServer.prepare_socket(
        ('127.0.0.1', 0),
        socket.AF_INET,
        socket.SOCK_STREAM,
        0,
        nodelay=True,
        ssl_adapter=None,
    )
    try:
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT) == 1
    finally:
        sock.close()
