# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import logging

from flask import request
from wazo_auth import exceptions, http, schemas

logger = logging.getLogger(__name__)


class Tenant(http.ErrorCatchingResource):

    def __init__(self, tenant_service):
        self.tenant_service = tenant_service

    @http.required_acl('auth.tenants.{tenant_uuid}.delete')
    def delete(self, tenant_uuid):
        logger.debug('deleting tenant %s', tenant_uuid)
        self.tenant_service.delete(tenant_uuid)
        return '', 204


class Tenants(http.ErrorCatchingResource):

    def __init__(self, tenant_service):
        self.tenant_service = tenant_service

    @http.required_acl('auth.tenants.read')
    def get(self):
        ListSchema = schemas.new_list_schema('name')
        list_params, errors = ListSchema().load(request.args)
        print list_params
        if errors:
            raise exceptions.InvalidListParamException(errors)

        for key, value in request.args.iteritems():
            if key in list_params:
                continue
            list_params[key] = value

        tenants = self.tenant_service.list_(**list_params)
        total = self.tenant_service.count(filtered=False, **list_params)
        filtered = self.tenant_service.count(filtered=True, **list_params)

        response = dict(
            filtered=filtered,
            total=total,
            items=tenants,
        )

        return response, 200

    @http.required_acl('auth.tenants.create')
    def post(self):
        logger.debug('create tenant %s', request.get_json(force=True))
        args, errors = schemas.TenantRequestSchema().load(request.get_json())
        if errors:
            raise exceptions.TenantParamException.from_errors(errors)

        result = self.tenant_service.new(**args)
        return result, 200


class Plugin(object):

    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['tenant_service'],)

        api.add_resource(Tenants, '/tenants', resource_class_args=args)
        api.add_resource(Tenant, '/tenants/<string:tenant_uuid>', resource_class_args=args)
