# Copyright 2017-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from flask import request
import marshmallow

from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Tenant


class _BaseResource(http.AuthResource):
    def __init__(self, tenant_service):
        self.tenant_service = tenant_service


class TenantUsers(_BaseResource):
    @http.required_acl('auth.tenants.{tenant_uuid}.users.read')
    def get(self, tenant_uuid):
        scoping_tenant = Tenant.autodetect()
        try:
            list_params = schemas.TenantUserListSchema().load(request.args)
        except marshmallow.ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        self.tenant_service.assert_tenant_under(scoping_tenant.uuid, tenant_uuid)

        return (
            {
                'items': self.tenant_service.list_users(tenant_uuid, **list_params),
                'total': self.tenant_service.count_users(
                    tenant_uuid, filtered=False, **list_params
                ),
                'filtered': self.tenant_service.count_users(
                    tenant_uuid, filtered=True, **list_params
                ),
            },
            200,
        )
