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

import logging
import signal
import sys

from multiprocessing import Process

from celery import Celery
from consul import Consul
from flask import Flask
from flask.ext.cors import CORS
from stevedore.dispatch import NameDispatchExtensionManager

from xivo_auth import http, token, extensions


logger = logging.getLogger(__name__)


class Controller(object):

    def __init__(self, config):
        self._config = config
        try:
            self._listen_addr = config['rest_api']['listen']
            self._listen_port = config['rest_api']['port']
            self._foreground = config['foreground']
            self._cors_config = config['rest_api']['cors']
            self._cors_enabled = self._cors_config['enabled']
            self._consul_config = config['consul']
            self._plugins = config['enabled_plugins']
        except KeyError:
            logger.error('Missing configuration to start the HTTP application')

        self._app = Flask(__name__)
        self._app.config.update(config)

        self._load_cors()

        celery = self._configure_celery()
        self._token_manager = token.Manager(config, Consul(**self._consul_config), celery)
        self._app.token_manager = self._token_manager

        self._app.config['backends'] = self._get_backends()
        self._app.register_blueprint(http.auth)

        self._celery_iface = _CeleryInterface(celery)
        self._celery_iface.start()
        signal.signal(signal.SIGTERM, self._sigterm_handler)

    def run(self):
        self._app.run(self._listen_addr, self._listen_port)
        self._celery_iface.join()

    def _sigterm_handler(self, _signo, _stack_frame):
        logger.info('SIGTERM received, leaving')
        sys.exit(0)

    def _load_cors(self):
        if self._cors_enabled:
            CORS(self._app, **self._cors_config)

    def _get_backends(self):
        loader = _PluginLoader(self._config)
        return loader.load()

    def _configure_celery(self):
        celery = Celery(self._app.import_name, broker=self._config['amqp']['uri'])
        celery.conf.update(self._app.config)
        celery.conf.update(
            CELERY_RESULT_BACKEND=self._app.config['amqp']['uri'],
            CELERY_ACCEPT_CONTENT=['json'],
            CELERY_TASK_SERIALIZER='json',
            CELERY_RESULT_SERIALIZER='json',
            CELERY_ALWAYS_EAGER=False,
            CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
            CELERY_DEFAULT_EXCHANGE_TYPE='topic',
            CELERYD_HIJACK_ROOT_LOGGER=False,
        )

        TaskBase = celery.Task
        app = self._app

        class ContextTask(TaskBase):
            abstract = True

            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return TaskBase.__call__(self, app, *args, **kwargs)

        celery.Task = ContextTask
        extensions.celery = celery
        from xivo_auth import events  # noqa
        return celery


class _CeleryInterface(Process):

    def __init__(self, celery):
        self.celery = celery
        super(_CeleryInterface, self).__init__()
        self.daemon = True
        sys.argv = [sys.argv[0]]  # celery does not like our command line arguments

    def run(self):
        logger.debug('Running celery worker')
        self.celery.worker_main()


class _PluginLoader(object):

    namespace = 'xivo_auth.backends'

    def __init__(self, config):
        self._enabled_plugins = config['enabled_plugins']
        self._config = config
        self._backends = NameDispatchExtensionManager(namespace=self.namespace,
                                                      check_func=self._check,
                                                      verify_requirements=False,
                                                      propagate_map_exceptions=True,
                                                      invoke_on_load=False)

    def load(self):
        self._backends.map(self._enabled_plugins, self._load)
        return self._backends

    def _check(self, plugin):
        return plugin.name in self._enabled_plugins

    def _load(self, extension):
        try:
            extension.obj = extension.plugin(self._config)
        except Exception:
            logger.exception('Failed to load %s', extension.name)
