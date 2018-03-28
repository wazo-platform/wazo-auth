# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from flask import request
from xivo import tenant_helpers

logger = logging.getLogger(__name__)


class Tenant(object):

    token_manager = None
    user_service = None

    def __init__(self, uuid, name=None):
        self.uuid = uuid
        self.name = name

    @classmethod
    def autodetect(cls, many=False):
        tenants = cls._autodetect()
        specified_tenant = request.headers.get('Wazo-Tenant')

        authorized_tenants = [t.uuid for t in tenants if t.uuid == specified_tenant]
        if specified_tenant and specified_tenant not in authorized_tenants:
            logger.debug('specified tenant not in available tenants')
            raise tenant_helpers.UnauthorizedTenant(specified_tenant)

        if many:
            return cls._many(tenants, specified_tenant)
        else:
            return cls._one(tenants, specified_tenant)

    @classmethod
    def _one(cls, tenants, specified_tenant):
        tenants = cls._many(tenants, specified_tenant)
        if not tenants:
            logger.debug('no tenant detected')
            raise tenant_helpers.InvalidTenant()

        if len(tenants) > 1:
            logger.debug('too many tenants detected')
            raise tenant_helpers.InvalidTenant()

        return tenants[0]

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
    def _get_user_tenants(cls, user_uuid):
        user_tenants = cls.user_service.list_tenants(user_uuid)
        return [cls(t['uuid'], t['name']) for t in user_tenants]

    @classmethod
    def setup(cls, token_manager, user_service):
        cls.token_manager = token_manager
        cls.user_service = user_service
