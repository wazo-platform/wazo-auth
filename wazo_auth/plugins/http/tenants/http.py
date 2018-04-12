# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from flask import request
from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Tenant as TenantDetector

logger = logging.getLogger(__name__)


class BaseResource(http.AuthResource):

    def __init__(self, tenant_service):
        self.tenant_service = tenant_service


class Tenant(BaseResource):

    @http.required_acl('auth.tenants.{tenant_uuid}.delete')
    def delete(self, tenant_uuid):
        top_tenant = TenantDetector.autodetect()

        logger.debug('deleting tenant %s from %s', tenant_uuid, top_tenant.uuid)

        self.tenant_service.delete(top_tenant.uuid, tenant_uuid)

        return '', 204

    @http.required_acl('auth.tenants.{tenant_uuid}.read')
    def get(self, tenant_uuid):
        top_tenant = TenantDetector.autodetect()
        return self.tenant_service.get(top_tenant.uuid, tenant_uuid)

    @http.required_acl('auth.tenants.{tenant_uuid}.edit')
    def put(self, tenant_uuid):
        top_tenant = TenantDetector.autodetect()
        args, errors = schemas.TenantSchema().load(request.get_json())
        if errors:
            raise exceptions.TenantParamException.from_errors(errors)

        result = self.tenant_service.update(top_tenant.uuid, tenant_uuid, **args)
        return result, 200


class Tenants(BaseResource):

    @http.required_acl('auth.tenants.read')
    def get(self):
        top_tenant = TenantDetector.autodetect()
        ListSchema = schemas.new_list_schema('name')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        tenants = self.tenant_service.list_(top_tenant.uuid, **list_params)
        total = self.tenant_service.count(top_tenant.uuid, filtered=False, **list_params)
        filtered = self.tenant_service.count(top_tenant.uuid, filtered=True, **list_params)

        response = {
            'filtered': filtered,
            'total': total,
            'items': tenants,
        }

        return response, 200

    @http.required_acl('auth.tenants.create')
    def post(self):
        top_tenant = TenantDetector.autodetect()
        logger.debug('creating sub-tenant of (%s): %s', top_tenant, request.get_json(force=True))
        args, errors = schemas.TenantSchema().load(request.get_json())
        if errors:
            raise exceptions.TenantParamException.from_errors(errors)

        result = self.tenant_service.new(parent_uuid=top_tenant.uuid, **args)
        return result, 200
