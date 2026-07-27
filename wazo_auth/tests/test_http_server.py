# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import socket
from unittest.mock import Mock, patch

from ..config import _DEFAULT_CONFIG
from ..http_server import CoreRestApi, ReusePortWSGIServer


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


def _core_rest_api(reuse_port):
    config = dict(_DEFAULT_CONFIG)
    config['rest_api'] = dict(config['rest_api'], reuse_port=reuse_port)
    return CoreRestApi(config, Mock(), Mock())


@patch('wazo_auth.http_server.wsgi.DynamicWSGIServer')
@patch('wazo_auth.http_server.ReusePortWSGIServer')
def test_run_uses_reuse_port_server_when_enabled(mock_reuse_server, mock_plain_server):
    _core_rest_api(reuse_port=True).run()

    mock_reuse_server.assert_called_once()
    mock_plain_server.assert_not_called()


@patch('wazo_auth.http_server.wsgi.DynamicWSGIServer')
@patch('wazo_auth.http_server.ReusePortWSGIServer')
def test_run_uses_plain_server_when_reuse_port_disabled(
    mock_reuse_server, mock_plain_server
):
    _core_rest_api(reuse_port=False).run()

    mock_plain_server.assert_called_once()
    mock_reuse_server.assert_not_called()
