# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import logging

from wazo_auth.services.idp import HARDCODED_IDP_TYPES

from . import bootstrap
from .database.helpers import db_session

logger = logging.getLogger(__name__)


def update_policy_on_startup(
    dao, default_policy_service, all_users_service, default_group_service
):
    with db_session():
        top_tenant_uuid = dao.tenant.find_top_tenant()
        visible_tenants = dao.tenant.list_visible_tenants(top_tenant_uuid)
        tenant_uuids = [tenant.uuid for tenant in visible_tenants]

    default_policy_service.update_policies(top_tenant_uuid)
    all_users_service.update_policies(tenant_uuids)
    default_group_service.update_groups(tenant_uuids)
    default_policy_service.delete_orphan_policies()


def create_initial_user(config):
    bootstrap.create_initial_user(
        config['bootstrap_user_username'],
        config['bootstrap_user_password'],
        config.get('bootstrap_user_purpose') or bootstrap.PURPOSE,
        bootstrap.AUTHENTICATION_METHOD,
        config.get('bootstrap_user_policy_slug') or bootstrap.DEFAULT_POLICY_SLUG,
    )


def check_unavailable_authentication_methods(dao, idp_plugins):
    """
    Detect missing implementations for authentication methods
    assigned to tenants and users
    """
    logger.info(
        'Checking configured authentication methods for missing implementations'
    )

    # compute available authentication methods from loaded idp plugins and hardcoded methods
    available_authentication_methods = (
        {
            getattr(extension.obj, 'authentication_method', None)
            for name, extension in idp_plugins.items()
        }
        if idp_plugins
        else set()
    )
    available_authentication_methods |= HARDCODED_IDP_TYPES
    logger.debug(
        '%d authentication methods are available',
        len(available_authentication_methods),
    )

    with db_session():
        # fetch tenants
        tenants = dao.tenant.get_missing_auth_methods(
            available_methods=available_authentication_methods
        )
        # fetch users
        users = dao.user.get_missing_auth_methods(
            available_methods=available_authentication_methods
        )

    tenants_authentication_methods = {
        tenant['default_authentication_method'] for tenant in tenants
    }
    tenants_missing_authentication_method = [
        tenant
        for tenant in tenants
        if tenant['default_authentication_method']
        not in available_authentication_methods
    ]
    logger.debug(
        '%d tenants have no available idp implementation',
        len(tenants_missing_authentication_method),
    )

    users_authentication_methods = {user['authentication_method'] for user in users}
    users_missing_authentication_method = [
        user
        for user in users
        if user['authentication_method'] not in available_authentication_methods
    ]
    logger.debug(
        '%d users have no available idp implementation',
        len(users_missing_authentication_method),
    )

    # compute in-use authentication methods
    all_authentication_methods = (
        tenants_authentication_methods | users_authentication_methods - {'default'}
    )
    logger.debug(
        '%d authentication methods are in use', len(all_authentication_methods)
    )

    missing_authentication_methods = (
        all_authentication_methods - available_authentication_methods
    )
    if missing_authentication_methods:
        logger.warning(
            '%d authentication methods have no available idp implementation',
            len(missing_authentication_methods),
        )
        for method in missing_authentication_methods:
            logger.warning(
                'Authentication method %s is in use but is not available', method
            )

    for tenant in tenants_missing_authentication_method:
        logger.warning(
            'Tenant (uuid=%s) has no available idp implementation '
            'for default authentication method %s',
            tenant['uuid'],
            tenant['default_authentication_method'],
        )
    for user in users_missing_authentication_method:
        logger.warning(
            'User (uuid=%s) has no available idp implementation '
            'for authentication method %s',
            user['uuid'],
            user['authentication_method'],
        )
