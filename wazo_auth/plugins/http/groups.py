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

from flask import request
from wazo_auth import exceptions, http, schemas


class Groups(http.ErrorCatchingResource):

    def __init__(self, group_service):
        self.group_service = group_service

    @http.required_acl('auth.groups.create')
    def post(self):
        args, errors = schemas.GroupRequestSchema().load(request.get_json())
        if errors:
            raise exceptions.GroupParamException.from_errors(errors)
        result = self.group_service.create(**args)
        return result, 200


class Plugin(object):

    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['group_service'],)

        api.add_resource(Groups, '/groups', resource_class_args=args)
