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

from wazo_auth import http

logger = logging.getLogger(__name__)


class _BaseResource(http.ErrorCatchingResource):

    def __init__(self, tenant_service):
        self.tenant_service = tenant_service


class TenantUser(_BaseResource):

    @http.required_acl('auth.tenants.{tenant_uuid}.users.edit')
    def delete(self, tenant_uuid, user_uuid):
        logger.debug('disassociating tenant %s user %s', tenant_uuid, user_uuid)
        self.tenant_service.remove_user(tenant_uuid, user_uuid)
        return '', 204

    @http.required_acl('auth.tenants.{tenant_uuid}.users.edit')
    def put(self, tenant_uuid, user_uuid):
        logger.debug('associating tenant %s user %s', tenant_uuid, user_uuid)
        self.tenant_service.add_user(tenant_uuid, user_uuid)
        return '', 204


class TenantUsers(_BaseResource):

    @http.required_acl('auth.tenants.{tenant_uuid}.users.read')
    def get(self, tenant_uuid):
        return {
            'items': self.tenant_service.list_users(tenant_uuid),
            'total': 0,
            'filtered': 0,
        }, 200


class UserTenants(_BaseResource):

    @http.required_acl('auth.users.{user_uuid}.tenants.read')
    def get(self, user_uuid):
        return {
            'items': [],
            'total': 0,
            'filtered': 0,
        }, 200


class Plugin(object):

    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['tenant_service'],)

        api.add_resource(
            TenantUser,
            '/tenants/<string:tenant_uuid>/users/<string:user_uuid>',
            resource_class_args=args,
        )
        api.add_resource(
            TenantUsers,
            '/tenants/<string:tenant_uuid>/users',
            resource_class_args=args,
        )

        api.add_resource(
            UserTenants,
            '/users/<string:user_uuid>/tenants',
            resource_class_args=args,
        )
