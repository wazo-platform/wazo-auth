# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest.mock import Mock, patch

import pytest

from wazo_auth.http_server import CoreRestApi, api, app, init_metrics


@pytest.fixture
def rest_api():
    config = {
        'rest_api': {
            'listen': '127.0.0.1',
            'port': 9497,
            'num_proxies': 1,
            'min_threads': 1,
            'max_threads': 1,
            'keep_alive_conn_limit': 256,
            'certificate': None,
            'private_key': None,
            'cors': {'enabled': False},
        },
    }
    return CoreRestApi(config, Mock(), Mock())


def test_stop_before_run_does_not_raise_and_sets_the_tombstone(rest_api):
    rest_api.stop()

    assert rest_api._stopped.is_set()


@patch('wazo_auth.http_server.wsgi')
def test_run_after_stop_does_not_start_the_server(wsgi, rest_api):
    rest_api.stop()
    rest_api.run()

    wsgi.DynamicWSGIServer.return_value.start.assert_not_called()


@patch('wazo_auth.http_server.wsgi')
def test_stop_after_run_stops_the_server(wsgi, rest_api):
    rest_api.run()
    rest_api.stop()

    wsgi.DynamicWSGIServer.return_value.stop.assert_called_once_with()


@patch('wazo_auth.http_server.init_flask_metrics')
def test_init_metrics_enabled_instruments_the_app(init_flask_metrics):
    init_metrics({'metrics': {'enabled': True}})

    init_flask_metrics.assert_called_once_with(app, api)


@patch('wazo_auth.http_server.init_flask_metrics')
def test_init_metrics_disabled_does_not_instrument_the_app(init_flask_metrics):
    init_metrics({'metrics': {'enabled': False}})

    init_flask_metrics.assert_not_called()
