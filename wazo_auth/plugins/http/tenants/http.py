# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from flask import request
from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Tenant as TenantDetector

from marshmallow import ValidationError

logger = logging.getLogger(__name__)


class BaseResource(http.AuthResource):
    def __init__(self, tenant_service):
        self.tenant_service = tenant_service


class Tenant(BaseResource):
    @http.required_acl('auth.tenants.{tenant_uuid}.delete')
    def delete(self, tenant_uuid):
        scoping_tenant = TenantDetector.autodetect()

        logger.debug('deleting tenant %s from %s', tenant_uuid, scoping_tenant.uuid)

        self.tenant_service.delete(scoping_tenant.uuid, tenant_uuid)

        return '', 204

    @http.required_acl('auth.tenants.{tenant_uuid}.read')
    def get(self, tenant_uuid):
        scoping_tenant = TenantDetector.autodetect()
        return self.tenant_service.get(scoping_tenant.uuid, tenant_uuid)

    @http.required_acl('auth.tenants.{tenant_uuid}.edit')
    def put(self, tenant_uuid):
        scoping_tenant = TenantDetector.autodetect()
        try:
            args = schemas.TenantSchema().load(request.get_json())
        except ValidationError as e:
            raise exceptions.TenantParamException.from_errors(e.messages)

        result = self.tenant_service.update(scoping_tenant.uuid, tenant_uuid, **args)
        return result, 200


class Tenants(BaseResource):
    @http.required_acl('auth.tenants.read')
    def get(self):
        scoping_tenant = TenantDetector.autodetect()
        try:
            list_params = schemas.TenantListSchema().load(request.args)
        except ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        tenants = self.tenant_service.list_(scoping_tenant.uuid, **list_params)
        total = self.tenant_service.count(
            scoping_tenant.uuid, filtered=False, **list_params
        )
        filtered = self.tenant_service.count(
            scoping_tenant.uuid, filtered=True, **list_params
        )

        response = {'filtered': filtered, 'total': total, 'items': tenants}

        return response, 200

    @http.required_acl('auth.tenants.create')
    def post(self):
        scoping_tenant = TenantDetector.autodetect()
        logger.debug(
            'creating sub-tenant of (%s): %s',
            scoping_tenant,
            request.get_json(force=True),
        )
        try:
            args = schemas.TenantSchema().load(request.get_json())
        except ValidationError as e:
            raise exceptions.TenantParamException.from_errors(e.messages)

        result = self.tenant_service.new(parent_uuid=scoping_tenant.uuid, **args)
        return result, 200
