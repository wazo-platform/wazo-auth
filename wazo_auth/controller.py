# Copyright 2015-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import signal
import sys
import threading
from collections import OrderedDict, UserDict
from functools import partial

from stevedore import driver
from stevedore.extension import Extension
from xivo import plugin_helpers
from xivo.consul_helpers import ServiceCatalogRegistration
from xivo.status import StatusAggregator

from wazo_auth.plugins.idp.native import NativeIDP
from wazo_auth.plugins.idp.refresh_token import RefreshTokenIDP

from . import bootstrap, http, services, token
from .bus import BusPublisher
from .database import queries
from .database.helpers import db_ready, init_db
from .flask_helpers import Tenant, Token
from .http_server import CoreRestApi, api
from .plugin_helpers import utils as plugin_utils
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
        self._backends = BackendsProxy()
        self._default_group_service = services.DefaultGroupService(
            self.dao,
            config['tenant_default_groups'],
        )
        self._tenant_service = services.TenantService(
            self.dao,
            config['all_users_policies'],
            self._default_group_service,
            self._bus_publisher,
        )
        self._saml_service = services.SAMLService(
            self._config, self._tenant_service, self.dao
        )

        self._saml_config_service = services.SAMLConfigService(
            self._config, self._saml_service, self.dao
        )

        email_notification_plugin = config['email_notification_plugin']
        logger.info("Loading driver plugin email: %s", email_notification_plugin)
        email_driver = driver.DriverManager(
            namespace='wazo_auth.email_notification',
            name=email_notification_plugin,
            invoke_on_load=True,
            invoke_kwds={
                'config': config,
                'template_formatter': template_formatter,
            },
        ).driver
        email_service = services.EmailService(
            self.dao,
            config,
            email_driver,
        )

        enabled_external_auth_plugins = [
            name
            for name, value in config['enabled_external_auth_plugins'].items()
            if value is True
        ]
        external_auth_service = services.ExternalAuthService(
            self.dao,
            config,
            self._bus_publisher,
            enabled_external_auth_plugins,
        )
        group_service = services.GroupService(self.dao)
        policy_service = services.PolicyService(self.dao)
        session_service = services.SessionService(self.dao, self._bus_publisher)
        self._user_service = services.UserService(self.dao, self._tenant_service)
        self._token_service = services.TokenService(
            config, self.dao, self._bus_publisher, self._user_service
        )
        self._default_policy_service = services.DefaultPolicyService(
            self.dao,
            config['default_policies'],
        )
        self._all_users_service = services.AllUsersService(
            self.dao,
            config['all_users_policies'],
        )

        ldap_service = services.LDAPService(self.dao)

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
        if backends:
            self._backends.set_backends(dict(backends.items()))

        self._config['loaded_plugins'] = self._loaded_plugins_names(
            self._backends.values()
        )

        # dependencies for idp plugins
        dependencies = {
            'backends': self._backends,
            'config': config,
            'group_service': group_service,
            'user_service': self._user_service,
            'policy_service': policy_service,
            'tenant_service': self._tenant_service,
            'token_service': self._token_service,
            'session_service': session_service,
            'ldap_service': ldap_service,
            'saml_service': self._saml_service,
            'saml_config_service': self._saml_config_service,
        }

        self._native_idp = NativeIDP()
        self._native_idp.load(dependencies)
        assert self._native_idp.loaded

        self._refresh_token_idp = RefreshTokenIDP()
        self._refresh_token_idp.load(dependencies)
        assert self._refresh_token_idp.loaded

        # load idp plugins (native and refresh_token are loaded separately)
        self._idp_plugins = None

        # NOTE: idp plugins have a priority since order of execution is important
        # and that priority should be preserved after load in the order plugins are used
        enabled_idps = sorted(
            (
                (name, plugin_params.get('priority', 100))
                for name, plugin_params in self._config['idp_plugins'].items()
                if plugin_params.get('enabled', False)
            ),
            key=lambda x: x[1],
        )
        enabled_idp_names = [name for name, _ in enabled_idps]
        if idp_plugins := plugin_utils.load_ordered(
            namespace='wazo_auth.idp',
            enabled=enabled_idp_names,
            load_args=(dependencies,),
        ):
            self._idp_plugins = idp_plugins
            for name, extension in self._idp_plugins.items():
                if not extension.obj.loaded:
                    logger.warning(
                        'idp plugin %s may not have been loaded successfully', name
                    )
                if not getattr(extension.obj, 'authentication_method', None):
                    logger.warning(
                        'idp plugin %s does not define an authentication_method attribute',
                        name,
                    )
        else:
            logger.info('no idp plugins loaded')

        # idp_plugins should be available in dependencies for http plugins
        dependencies['idp_plugins'] = (
            OrderedDict(
                (name, extension.obj)
                for name, extension in self._idp_plugins.items()
                if extension.obj.loaded
            )
            if self._idp_plugins
            else OrderedDict()
        )

        authentication_service = services.AuthenticationService(
            self.dao,
            self._backends,
            self._tenant_service,
            self._saml_service,
            dependencies['idp_plugins'],
            self._native_idp,
            self._refresh_token_idp,
        )

        self._idp_service = services.IDPService(self.dao, dependencies['idp_plugins'])

        dependencies = {
            'api': api,
            'status_aggregator': self.status_aggregator,
            'authentication_service': authentication_service,
            'email_service': email_service,
            'external_auth_service': external_auth_service,
            'idp_service': self._idp_service,
            'user_service': self._user_service,
            'token_manager': self._token_service,  # For compatibility only
            'template_formatter': template_formatter,
            **dependencies,
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
            config, self.dao, self._bus_publisher, self._saml_service
        )

    def run(self):
        signal.signal(signal.SIGTERM, partial(_signal_handler, self))
        signal.signal(signal.SIGINT, partial(_signal_handler, self))

        with db_ready(timeout=self._config['db_connect_retry_timeout_seconds']):
            if self._config['update_policy_on_startup']:
                self._update_policy_on_startup()
            http.init_top_tenant(self.dao)
            if self._config['bootstrap_user_on_startup']:
                bootstrap.create_initial_user(
                    self._config['db_uri'],
                    self._config['bootstrap_user_username'],
                    self._config['bootstrap_user_password'],
                    self._config.get('bootstrap_user_purpose') or bootstrap.PURPOSE,
                    bootstrap.AUTHENTICATION_METHOD,
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

    def _update_policy_on_startup(self):
        top_tenant_uuid = self.dao.tenant.find_top_tenant()
        visible_tenants = self.dao.tenant.list_visible_tenants(top_tenant_uuid)
        tenant_uuids = [tenant.uuid for tenant in visible_tenants]

        self._default_policy_service.update_policies(top_tenant_uuid)
        self._all_users_service.update_policies(tenant_uuids)
        self._default_group_service.update_groups(tenant_uuids)
        self._default_policy_service.delete_orphan_policies()


class BackendsProxy(UserDict[str, Extension]):
    def set_backends(self, backends: dict[str, Extension]):
        self.data = backends
