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

from flask import current_app, request
from wazo_auth import exceptions, http, schemas

logger = logging.getLogger(__name__)


class Tenants(http.ErrorCatchingResource):

    @http.required_acl('auth.tenants.create')
    def post(self):
        logger.debug('create tenant %s', request.get_json(force=True))
        args, errors = schemas.TenantRequestSchema().load(request.get_json())
        if errors:
            raise exceptions.TenantParamException.from_errors(errors)

        tenant_service = current_app.config['tenant_service']
        result = tenant_service.new_tenant(**args)
        return result, 200


class Plugin(object):

    def __init__(self, api):
        api.add_resource(Tenants, '/tenants')
