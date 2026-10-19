# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest.mock import patch

from flask import Flask
from flask_restful import Api

from ..plugin import Plugin


@patch('wazo_auth.plugins.http.metrics.plugin.init_flask_metrics')
def test_load_instruments_the_api_app(init_flask_metrics):
    app = Flask('test')
    api = Api(app, prefix='/0.1')

    Plugin().load({'api': api})

    init_flask_metrics.assert_called_once_with(app, api)
