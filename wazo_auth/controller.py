# Copyright 2015-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import signal
import sys

from functools import partial

from xivo import plugin_helpers
from xivo.consul_helpers import ServiceCatalogRegistration
from xivo.status import StatusAggregator

from . import bus, services, token
from .database import queries
from .database.helpers import init_db
from .flask_helpers import Tenant
from .helpers import LocalTokenRenewer
from .http_server import api, CoreRestApi
from .purpose import Purposes
from .service_discovery import self_check

logger = logging.getLogger(__name__)


def _sigterm_handler(controller, signum, frame):
    controller.stop(reason='SIGTERM')


def _check_required_config_for_other_threads(config):
    try:
        config['debug']
    except KeyError as e:
        logger.error('Missing configuration to start the application: %s', e)
        sys.exit(1)


class Controller:
    def __init__(self, config):
        init_db(config['db_uri'], max_connections=config['rest_api']['max_threads'])
        self._config = config
        _check_required_config_for_other_threads(config)
        self._service_discovery_args = [
            'wazo-auth',
            config.get('uuid'),
            config['consul'],
            config['service_discovery'],
            config['amqp'],
            partial(self_check, config),
        ]

        self.status_aggregator = StatusAggregator()
        template_formatter = services.helpers.TemplateFormatter(config)
        self._bus_publisher = bus.BusPublisher(config)
        dao = queries.DAO.from_defaults()
        self._tenant_tree = services.helpers.TenantTree(dao.tenant)
        self._backends = BackendsProxy()
        authentication_service = services.AuthenticationService(dao, self._backends)
        email_service = services.EmailService(
            dao, self._tenant_tree, config, template_formatter
        )
        enabled_external_auth_plugins = [
            name
            for name, value in config['enabled_external_auth_plugins'].items()
            if value is True
        ]
        external_auth_service = services.ExternalAuthService(
            dao,
            self._tenant_tree,
            config,
            self._bus_publisher,
            enabled_external_auth_plugins,
        )
        group_service = services.GroupService(dao, self._tenant_tree)
        policy_service = services.PolicyService(dao, self._tenant_tree)
        session_service = services.SessionService(
            dao, self._tenant_tree, self._bus_publisher
        )
        self._user_service = services.UserService(dao, self._tenant_tree, group_service)
        self._token_service = services.TokenService(
            config, dao, self._tenant_tree, self._bus_publisher, self._user_service
        )
        self._tenant_service = services.TenantService(
            dao,
            self._tenant_tree,
            group_service,
            policy_service,
            config['all_users_policies'],
            self._bus_publisher,
        )

        self._metadata_plugins = plugin_helpers.load(
            namespace='wazo_auth.metadata',
            names=self._config['enabled_metadata_plugins'],
            dependencies={
                'user_service': self._user_service,
                'group_service': group_service,
                'tenant_service': self._tenant_service,
                'token_service': self._token_service,
                'backends': self._backends,
                'config': config,
            },
        )

        self._purposes = Purposes(
            self._config['purpose_metadata_mapping'], self._metadata_plugins
        )

        backends = plugin_helpers.load(
            namespace='wazo_auth.backends',
            names=self._config['enabled_backend_plugins'],
            dependencies={
                'user_service': self._user_service,
                'group_service': group_service,
                'tenant_service': self._tenant_service,
                'purposes': self._purposes,
                'config': config,
            },
        )
        self._backends.set_backends(backends)
        self._config['loaded_plugins'] = self._loaded_plugins_names(self._backends)
        dependencies = {
            'api': api,
            'status_aggregator': self.status_aggregator,
            'authentication_service': authentication_service,
            'backends': self._backends,
            'config': config,
            'email_service': email_service,
            'external_auth_service': external_auth_service,
            'group_service': group_service,
            'user_service': self._user_service,
            'token_service': self._token_service,
            'token_manager': self._token_service,  # For compatibility only
            'policy_service': policy_service,
            'tenant_service': self._tenant_service,
            'session_service': session_service,
            'template_formatter': template_formatter,
        }
        Tenant.setup(self._token_service, self._user_service, self._tenant_service)

        plugin_helpers.load(
            namespace='wazo_auth.http',
            names=config['enabled_http_plugins'],
            dependencies=dependencies,
        )
        manager = plugin_helpers.load(
            namespace='wazo_auth.external_auth',
            names=config['enabled_external_auth_plugins'],
            dependencies=dependencies,
        )

        config['external_auth_plugin_info'] = {}
        if manager:
            for extension in manager:
                plugin_info = getattr(extension.obj, 'plugin_info', {})
                config['external_auth_plugin_info'][extension.name] = plugin_info

        self._rest_api = CoreRestApi(config, self._token_service, self._user_service)

        self._expired_token_remover = token.ExpiredTokenRemover(
            config, dao, self._bus_publisher
        )

    def run(self):
        signal.signal(signal.SIGTERM, partial(_sigterm_handler, self))

        with bus.publisher_thread(self._bus_publisher):
            with ServiceCatalogRegistration(*self._service_discovery_args):
                self._expired_token_remover.start()
                local_token_renewer = self._get_local_token_renewer()
                self._config['local_token_renewer'] = local_token_renewer
                self._rest_api.run()
                local_token_renewer.revoke_token()

    def stop(self, reason):
        logger.warning('Stopping wazo-auth: %s', reason)
        self._expired_token_remover.stop()
        self._rest_api.stop()

    def _get_local_token_renewer(self):
        try:
            backend = self._backends['wazo_user']
        except KeyError:
            logger.info(
                'wazo_user disabled no internal token will be created for wazo-auth'
            )
            return

        return LocalTokenRenewer(backend, self._token_service, self._user_service)

    def _loaded_plugins_names(self, backends):
        return [backend.name for backend in backends]


class BackendsProxy:
    def __init__(self):
        self._backends = {}

    def set_backends(self, backends):
        self._backends = backends

    def __getitem__(self, key):
        return self._backends[key]

    def __iter__(self):
        return iter(self._backends)
