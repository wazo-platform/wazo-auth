# Copyright 2015-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import signal
import sys
import threading
from functools import partial

from xivo import plugin_helpers
from xivo.consul_helpers import ServiceCatalogRegistration
from xivo.status import StatusAggregator

from . import bootstrap, http, services, token
from .bus import BusPublisher
from .database import queries
from .database.helpers import db_ready, init_db
from .flask_helpers import Tenant, Token
from .http_server import CoreRestApi, api
from .purpose import Purposes
from .service_discovery import self_check

logger = logging.getLogger(__name__)


def _signal_handler(controller, signum, frame):
    controller.stop(reason=signal.Signals(signum).name)


def _check_required_config_for_other_threads(config):
    try:
        config['debug']
    except KeyError as e:
        logger.error('Missing configuration to start the application: %s', e)
        sys.exit(1)


class Controller:
    def __init__(self, config):
        init_db(config['db_uri'], pool_size=config['rest_api']['max_threads'])
        self._config = config
        self._stopping_thread = None
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

        self._bus_publisher = BusPublisher.from_config(config['uuid'], config['amqp'])

        self.dao = queries.DAO.from_defaults()
        self._tenant_tree = services.helpers.TenantTree(self.dao.tenant)
        self._backends = BackendsProxy()
        authentication_service = services.AuthenticationService(
            self.dao, self._backends
        )
        email_service = services.EmailService(
            self.dao, self._tenant_tree, config, template_formatter
        )
        enabled_external_auth_plugins = [
            name
            for name, value in config['enabled_external_auth_plugins'].items()
            if value is True
        ]
        external_auth_service = services.ExternalAuthService(
            self.dao,
            self._tenant_tree,
            config,
            self._bus_publisher,
            enabled_external_auth_plugins,
        )
        group_service = services.GroupService(self.dao, self._tenant_tree)
        policy_service = services.PolicyService(self.dao, self._tenant_tree)
        session_service = services.SessionService(
            self.dao, self._tenant_tree, self._bus_publisher
        )
        self._user_service = services.UserService(self.dao, self._tenant_tree)
        self._token_service = services.TokenService(
            config, self.dao, self._tenant_tree, self._bus_publisher, self._user_service
        )
        self._default_group_service = services.DefaultGroupService(
            self.dao,
            config['tenant_default_groups'],
        )
        self._tenant_service = services.TenantService(
            self.dao,
            self._tenant_tree,
            config['all_users_policies'],
            self._default_group_service,
            self._bus_publisher,
        )
        self._default_policy_service = services.DefaultPolicyService(
            self.dao,
            config['default_policies'],
        )
        self._all_users_service = services.AllUsersService(
            self.dao,
            config['all_users_policies'],
        )

        ldap_service = services.LDAPService(self.dao, self._tenant_tree)

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
                'ldap_service': ldap_service,
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
            'ldap_service': ldap_service,
        }
        Tenant.setup(self._token_service, self._user_service, self._tenant_service)
        Token.setup(self._token_service)

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
            config, self.dao, self._bus_publisher
        )

    def run(self):
        signal.signal(signal.SIGTERM, partial(_signal_handler, self))
        signal.signal(signal.SIGINT, partial(_signal_handler, self))

        with db_ready(timeout=self._config['db_connect_retry_timeout_seconds']):
            if self._config['update_policy_on_startup']:
                self._default_policy_service.update_policies()
                self._all_users_service.update_policies()
                self._default_group_service.update_groups()
                self._default_policy_service.delete_orphan_policies()
            http.init_top_tenant(self.dao)
            if self._config['bootstrap_user_on_startup']:
                bootstrap.create_initial_user(
                    self._config['db_uri'],
                    self._config['bootstrap_user_username'],
                    self._config['bootstrap_user_password'],
                    self._config.get('bootstrap_user_purpose') or bootstrap.PURPOSE,
                    self._config.get('bootstrap_user_policy_slug')
                    or bootstrap.DEFAULT_POLICY_SLUG,
                )

        try:
            with ServiceCatalogRegistration(*self._service_discovery_args):
                self._expired_token_remover.start()
                self._rest_api.run()
        finally:
            if self._stopping_thread:
                self._stopping_thread.join()

    def stop(self, reason):
        logger.warning('Stopping wazo-auth: %s', reason)
        self._expired_token_remover.stop()
        self._stopping_thread = threading.Thread(
            target=self._rest_api.stop, name=reason
        )
        self._stopping_thread.start()

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
