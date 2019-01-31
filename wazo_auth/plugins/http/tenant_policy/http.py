# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from flask import request
from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Tenant


logger = logging.getLogger(__name__)


class TenantPolicies(http.AuthResource):

    def __init__(self, tenant_service):
        self.tenant_service = tenant_service

    @http.required_acl('auth.tenants.{tenant_uuid}.users.read')
    def get(self, tenant_uuid):
        scoping_tenant = Tenant.autodetect()
        ListSchema = schemas.new_list_schema('name')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        list_params['scoping_tenant_uuid'] = scoping_tenant.uuid
        total = self.tenant_service.count_policies(tenant_uuid, filtered=False, **list_params)
        filtered = self.tenant_service.count_policies(tenant_uuid, filtered=True, **list_params)

        return {
            'items': self.tenant_service.list_policies(tenant_uuid, **list_params),
            'total': total,
            'filtered': filtered,
        }, 200
