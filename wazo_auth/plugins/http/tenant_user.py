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


class _BaseResource(http.ErrorCatchingResource):

    def __init__(self, tenant_service):
        self.tenant_service = tenant_service


class TenantUser(_BaseResource):

    @http.required_acl('auth.tenants.{tenant_uuid}.users.{user_uuid}.delete')
    def delete(self, tenant_uuid, user_uuid):
        logger.debug('disassociating tenant %s user %s', tenant_uuid, user_uuid)
        self.tenant_service.remove_user(tenant_uuid, user_uuid)
        return '', 204

    @http.required_acl('auth.tenants.{tenant_uuid}.users.{user_uuid}.create')
    def put(self, tenant_uuid, user_uuid):
        logger.debug('associating tenant %s user %s', tenant_uuid, user_uuid)
        self.tenant_service.add_user(tenant_uuid, user_uuid)
        return '', 204


class TenantUsers(_BaseResource):

    @http.required_acl('auth.tenants.{tenant_uuid}.users.read')
    def get(self, tenant_uuid):
        ListSchema = schemas.new_list_schema('username')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        for key, value in request.args.iteritems():
            if key in list_params:
                continue
            list_params[key] = value

        return {
            'items': self.tenant_service.list_users(tenant_uuid, **list_params),
            'total': self.tenant_service.count_users(tenant_uuid, filtered=False, **list_params),
            'filtered': self.tenant_service.count_users(tenant_uuid, filtered=True, **list_params),
        }, 200


class UserTenants(http.ErrorCatchingResource):

    def __init__(self, user_service):
        self.user_service = user_service

    @http.required_acl('auth.users.{user_uuid}.tenants.read')
    def get(self, user_uuid):
        ListSchema = schemas.new_list_schema('name')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        for key, value in request.args.iteritems():
            if key in list_params:
                continue
            list_params[key] = value

        return {
            'items': self.user_service.list_tenants(user_uuid, **list_params),
            'total': self.user_service.count_tenants(user_uuid, filtered=False, **list_params),
            'filtered': self.user_service.count_tenants(user_uuid, filtered=True, **list_params),
        }, 200


class Plugin(object):

    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['tenant_service'],)

        api.add_resource(
            TenantUser,
            '/tenants/<uuid:tenant_uuid>/users/<uuid:user_uuid>',
            resource_class_args=args,
        )
        api.add_resource(
            TenantUsers,
            '/tenants/<uuid:tenant_uuid>/users',
            resource_class_args=args,
        )

        api.add_resource(
            UserTenants,
            '/users/<uuid:user_uuid>/tenants',
            resource_class_args=(dependencies['user_service'],),
        )
