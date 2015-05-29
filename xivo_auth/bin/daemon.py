# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Avencall
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import signal
import logging
import sys

from flask import Flask
from consul import Consul
from xivo.user_rights import change_user
from xivo.daemonize import pidfile_context
from xivo.xivo_logging import setup_logging
from xivo_auth import extensions
from xivo_auth import http
from xivo_auth.config import get_config
from xivo_auth.core import plugin_manager
from xivo_auth.core.celery_interface import make_celery, CeleryInterface
from xivo_auth import successful_auth_signal, token_removal_signal, get_token_data_signal
from flask.ext.cors import CORS

logger = logging.getLogger(__name__)


class _Controller(object):

    def __init__(self, config):
        try:
            self._listen_addr = config['rest_api']['listen']
            self._listen_port = config['rest_api']['port']
            self._foreground = config['foreground']
            self._cors_config = config['rest_api']['cors']
            self._cors_enabled = self._cors_config['enabled']
            self._consul_config = config['consul']
        except KeyError:
            logger.error('Missing configuration to start the HTTP application')

        self._app = Flask(__name__)
        self._app.config.update(config)

        self.load_cors()

        extensions.celery = make_celery(self._app)
        extensions.consul = Consul(**self._consul_config)

        self.register_signal_handlers()

        backends = plugin_manager.load_plugins(self._app, config)
        self._app.config['backends'] = backends
        self._app.register_blueprint(http.auth)

        sys.argv = [sys.argv[0]]  # For the celery process
        self._celery_iface = CeleryInterface(extensions.celery)
        self._celery_iface.daemon = True
        self._celery_iface.start()
        signal.signal(signal.SIGTERM, self.sigterm_handler)

    def run(self):
        self._app.run(self._listen_addr, self._listen_port)
        self._celery_iface.join()

    def sigterm_handler(self, _signo, _stack_frame):
        logger.info('SIGTERM received, leaving')
        sys.exit(0)

    def register_signal_handlers(self):
        from xivo_auth.events import on_auth_success, remove_token, fetch_token_data
        get_token_data_signal.connect(fetch_token_data, self._app)
        successful_auth_signal.connect(on_auth_success, self._app)
        token_removal_signal.connect(remove_token, self._app)

    def load_cors(self):
        if self._cors_enabled:
            CORS(self._app, **self._cors_config)


def main():
    config = get_config(sys.argv[1:])

    setup_logging(config['log_filename'], config['foreground'], config['debug'], config['log_level'])
    user = config.get('user')
    if user:
        change_user(user)

    controller = _Controller(config)
    with pidfile_context(config['pid_filename'], config['foreground']):
        controller.run()
