# Copyright 2015-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging
import signal
import sys

from functools import partial

from cheroot import wsgi
from xivo import http_helpers, plugin_helpers
from xivo.http_helpers import ReverseProxied
from xivo.consul_helpers import ServiceCatalogRegistration
from werkzeug.contrib.fixers import ProxyFix

from . import bus, http, services, token
from .database import queries
from .flask_helpers import Tenant
from .helpers import LocalTokenManager
from .service_discovery import self_check

logger = logging.getLogger(__name__)


def _signal_handler(signum, frame):
    sys.exit(0)


class Controller:

    def __init__(self, config):
        self._config = config
        try:
            self._listen_addr = config['rest_api']['https']['listen']
            self._listen_port = config['rest_api']['https']['port']
            self._foreground = config['foreground']
            self._consul_config = config['consul']
            self._service_discovery_config = config['service_discovery']
            self._plugins = config['enabled_backend_plugins']
            self._bus_config = config['amqp']
            self._log_level = config['log_level']
            self._debug = config['debug']
            self._bind_addr = (self._listen_addr, self._listen_port)
            self._ssl_cert_file = config['rest_api']['https']['certificate']
            self._ssl_key_file = config['rest_api']['https']['private_key']
            self._max_threads = config['rest_api']['max_threads']
            self._xivo_uuid = config.get('uuid')
            logger.debug('private key: %s', self._ssl_key_file)
        except KeyError as e:
            logger.error('Missing configuration to start the application: %s', e)
            sys.exit(1)

        template_formatter = services.helpers.TemplateFormatter(config)
        self._bus_publisher = bus.BusPublisher(config)
        dao = queries.DAO.from_config(self._config)
        self._tenant_tree = services.helpers.TenantTree(dao.tenant)
        self._token_manager = token.Manager(config, dao, self._tenant_tree)
        email_service = services.EmailService(dao, self._tenant_tree, config, template_formatter)
        external_auth_service = services.ExternalAuthService(
            dao, self._tenant_tree, config, self._bus_publisher, config['enabled_external_auth_plugins'])
        group_service = services.GroupService(dao, self._tenant_tree)
        policy_service = services.PolicyService(dao, self._tenant_tree)
        self._user_service = services.UserService(dao, self._tenant_tree)
        self._tenant_service = services.TenantService(dao, self._tenant_tree, self._bus_publisher)
        self._metadata_plugins = plugin_helpers.load(
            'wazo_auth.metadata',
            self._config['enabled_metadata_plugins'],
            {'user_service': self._user_service,
             'group_service': group_service,
             'config': config},
        )
        self._backends = plugin_helpers.load(
            'wazo_auth.backends',
            self._config['enabled_backend_plugins'],
            {'user_service': self._user_service,
             'group_service': group_service,
             'tenant_service': self._tenant_service,
             'metadata_plugins': self._metadata_plugins,
             'config': config},
        )
        self._config['loaded_plugins'] = self._loaded_plugins_names(self._backends)
        dependencies = {
            'backends': self._backends,
            'config': config,
            'email_service': email_service,
            'external_auth_service': external_auth_service,
            'group_service': group_service,
            'user_service': self._user_service,
            'token_manager': self._token_manager,
            'policy_service': policy_service,
            'tenant_service': self._tenant_service,
            'template_formatter': template_formatter,
        }
        Tenant.setup(self._token_manager, self._user_service, self._tenant_service)
        self._flask_app = http.new_app(dependencies)
        self._expired_token_remover = token.ExpiredTokenRemover(config, dao)

    def run(self):
        signal.signal(signal.SIGTERM, _signal_handler)
        wsgi_app = ReverseProxied(ProxyFix(wsgi.WSGIPathInfoDispatcher({'/': self._flask_app})))
        server = wsgi.WSGIServer(bind_addr=self._bind_addr,
                                 wsgi_app=wsgi_app,
                                 numthreads=self._max_threads)
        server.ssl_adapter = http_helpers.ssl_adapter(self._ssl_cert_file,
                                                      self._ssl_key_file)

        with bus.publisher_thread(self._bus_publisher):
            with ServiceCatalogRegistration('wazo-auth',
                                            self._xivo_uuid,
                                            self._consul_config,
                                            self._service_discovery_config,
                                            self._bus_config,
                                            partial(self_check,
                                                    self._listen_port)):
                self._expired_token_remover.run()
                local_token_manager = self._get_local_token_manager()
                self._config['local_token_manager'] = local_token_manager
                try:
                    server.start()
                finally:
                    server.stop()
                local_token_manager.revoke_token()

    def _get_local_token_manager(self):
        try:
            backend = self._backends['xivo_service']
        except KeyError:
            logger.info('xivo_service disabled no service token will be created for wazo-auth')
            return

        return LocalTokenManager(backend, self._token_manager)

    def _loaded_plugins_names(self, backends):
        return [backend.name for backend in backends]
