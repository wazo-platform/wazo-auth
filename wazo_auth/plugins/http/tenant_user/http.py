# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from flask import request
from wazo_auth import exceptions, http, schemas

logger = logging.getLogger(__name__)


class _BaseResource(http.AuthResource):

    def __init__(self, tenant_service):
        self.tenant_service = tenant_service


class TenantUsers(_BaseResource):

    @http.required_acl('auth.tenants.{tenant_uuid}.users.read')
    def get(self, tenant_uuid):
        ListSchema = schemas.new_list_schema('username')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        return {
            'items': self.tenant_service.list_users(tenant_uuid, **list_params),
            'total': self.tenant_service.count_users(tenant_uuid, filtered=False, **list_params),
            'filtered': self.tenant_service.count_users(tenant_uuid, filtered=True, **list_params),
        }, 200


class UserTenants(http.AuthResource):

    def __init__(self, user_service):
        self.user_service = user_service

    @http.required_acl('auth.users.{user_uuid}.tenants.read')
    def get(self, user_uuid):
        ListSchema = schemas.new_list_schema('name')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        return {
            'items': self.user_service.list_tenants(user_uuid, **list_params),
            'total': self.user_service.count_tenants(user_uuid, filtered=False, **list_params),
            'filtered': self.user_service.count_tenants(user_uuid, filtered=True, **list_params),
        }, 200
