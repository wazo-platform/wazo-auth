# Copyright 2018-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from flask import request
from xivo import tenant_helpers

logger = logging.getLogger(__name__)


class Tenant:

    token_service = None
    user_service = None
    tenant_service = None

    def __init__(self, uuid, name=None):
        self.uuid = uuid
        self.name = name

    @classmethod
    def autodetect(cls):
        specified_tenant = request.headers.get('Wazo-Tenant')
        token = cls._get_token()
        user_uuid = token.metadata.get('uuid')
        logger.debug('token.metadata %s', token.metadata)
        logger.debug('user_uuid: %s', user_uuid)
        if user_uuid:
            user_tenant = cls._get_user_tenant(user_uuid)
        else:
            user_tenant = token.metadata.get('tenant_uuid')
        logger.debug('user_tenant: %s', user_tenant)

        if not specified_tenant:
            return cls(user_tenant)

        if specified_tenant == user_tenant:
            return cls(user_tenant)

        sub_tenants = cls._get_all_sub_tenants(user_tenant)
        if specified_tenant in sub_tenants:
            return cls(specified_tenant)

        raise tenant_helpers.UnauthorizedTenant(specified_tenant)

    @classmethod
    def _get_token(cls):
        token_uuid = request.headers.get('X-Auth-Token')
        return cls._get_token_data(token_uuid)

    @classmethod
    def _get_token_data(cls, token_uuid):
        return cls.token_service.get(token_uuid, required_access=None)

    @classmethod
    def _get_user_tenant(cls, user_uuid):
        user = cls.user_service.get_user(user_uuid)
        return user['tenant_uuid']

    @classmethod
    def _get_all_sub_tenants(cls, tenant_uuid):
        return cls.tenant_service.list_sub_tenants(tenant_uuid)

    @classmethod
    def setup(cls, token_service, user_service, tenant_service):
        cls.token_service = token_service
        cls.user_service = user_service
        cls.tenant_service = tenant_service


class Token:

    token_service = None

    @classmethod
    def setup(cls, token_service):
        cls.token_service = token_service

    @classmethod
    def from_headers(cls):
        token_uuid = request.headers.get('X-Auth-Token')
        return cls.token_service.get(token_uuid, required_access=None)
