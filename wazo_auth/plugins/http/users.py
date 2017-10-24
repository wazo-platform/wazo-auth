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

from flask import current_app, request
from wazo_auth import exceptions, http, schemas


class User(http.ErrorCatchingResource):

    @http.required_acl('auth.users.{user_uuid}.read')
    def get(self, user_uuid):
        user_service = current_app.config['user_service']
        return user_service.get_user(user_uuid)

    @http.required_acl('auth.users.{user_uuid}.delete')
    def delete(self, user_uuid):
        user_service = current_app.config['user_service']
        user_service.delete_user(user_uuid)
        return '', 204


class Users(http.ErrorCatchingResource):

    @http.required_acl('auth.users.read')
    def get(self):
        ListSchema = schemas.new_list_schema('username')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        for key, value in request.args.iteritems():
            if key in list_params:
                continue
            list_params[key] = value

        user_service = current_app.config['user_service']

        users = user_service.list_users(**list_params)
        total = user_service.count_users(filtered=False, **list_params)
        filtered = user_service.count_users(filtered=True, **list_params)

        response = dict(
            filtered=filtered,
            total=total,
            items=users,
        )

        return response, 200

    def post(self):
        user_service = current_app.config['user_service']
        args, errors = schemas.UserRequestSchema().load(request.get_json(force=True))
        if errors:
            raise exceptions.UserParamException.from_errors(errors)
        result = user_service.new_user(**args)
        return result, 200


class Plugin(object):

    def __init__(self, api):
        self.add_resources(api)

    def add_resources(self, api):
        api.add_resource(Users, '/users')
        api.add_resource(User, '/users/<string:user_uuid>')
