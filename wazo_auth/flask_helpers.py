# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from flask import request
from xivo import tenant_helpers

logger = logging.getLogger(__name__)


class Tenant:

    token_manager = None
    user_service = None
    tenant_service = None

    def __init__(self, uuid, name=None):
        self.uuid = uuid
        self.name = name

    @classmethod
    def autodetect(cls, many=False):
        specified_tenant = request.headers.get('Wazo-Tenant')

        if not many:
            return cls._one(specified_tenant)

        tenants = cls._autodetect()

        authorized_tenants = [t.uuid for t in tenants if t.uuid == specified_tenant]
        if specified_tenant and specified_tenant not in authorized_tenants:
            logger.debug('specified tenant not in available tenants')
            raise tenant_helpers.UnauthorizedTenant(specified_tenant)

        return cls._many(tenants, specified_tenant)

    @classmethod
    def _one(cls, specified_tenant):
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
    def _many(cls, tenants, specified_tenant):
        if specified_tenant:
            tenants = [t for t in tenants if t.uuid == specified_tenant]
        return tenants

    @classmethod
    def _autodetect(cls):
        token = cls._get_token()
        user_uuid = token.metadata.get('uuid')
        if user_uuid:
            return cls._get_user_tenants(user_uuid)

        return [cls(t['uuid'], t['name']) for t in token.metadata['tenants']]

    @classmethod
    def _get_token(cls):
        token_uuid = request.headers.get('X-Auth-Token')
        return cls._get_token_data(token_uuid)

    @classmethod
    def _get_token_data(cls, token_uuid):
        return cls.token_manager.get(token_uuid, required_acl=None)

    @classmethod
    def _get_user_tenant(cls, user_uuid):
        user = cls.user_service.get_user(user_uuid)
        return user['tenant_uuid']

    @classmethod
    def _get_user_tenants(cls, user_uuid):
        user_tenants = cls.user_service.list_tenants(user_uuid)
        return [cls(t['uuid'], t['name']) for t in user_tenants]

    @classmethod
    def _get_all_sub_tenants(cls, tenant_uuid):
        return cls.tenant_service.list_sub_tenants(tenant_uuid)

    @classmethod
    def setup(cls, token_manager, user_service, tenant_service):
        cls.token_manager = token_manager
        cls.user_service = user_service
        cls.tenant_service = tenant_service
