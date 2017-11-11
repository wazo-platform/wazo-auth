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


class _BaseGroupResource(http.ErrorCatchingResource):

    def __init__(self, group_service):
        self.group_service = group_service


class Group(_BaseGroupResource):

    @http.required_acl('auth.groups.{group_uuid}.delete')
    def delete(self, group_uuid):
        self.group_service.delete(group_uuid)
        return '', 204


class Groups(_BaseGroupResource):

    @http.required_acl('auth.groups.read')
    def get(self):
        ListSchema = schemas.new_list_schema('name')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        for key, value in request.args.iteritems():
            if key in list_params:
                continue
            list_params[key] = value

        groups = self.group_service.list_(**list_params)
        total = self.group_service.count(filtered=False, **list_params)
        filtered = self.group_service.count(filtered=True, **list_params)

        response = dict(
            filtered=filtered,
            total=total,
            items=groups,
        )

        return response, 200

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

        api.add_resource(Group, '/groups/<string:group_uuid>', resource_class_args=args)
        api.add_resource(Groups, '/groups', resource_class_args=args)
