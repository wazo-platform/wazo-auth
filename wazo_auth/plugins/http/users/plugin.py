# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from flask import current_app, request
from wazo_auth import exceptions, http, schemas


class User(http.ErrorCatchingResource):

    def __init__(self, user_service):
        self.user_service = user_service

    @http.required_acl('auth.users.{user_uuid}.read')
    def get(self, user_uuid):
        return self.user_service.get_user(user_uuid)

    @http.required_acl('auth.users.{user_uuid}.delete')
    def delete(self, user_uuid):
        self.user_service.delete_user(user_uuid)
        return '', 204


class Users(http.ErrorCatchingResource):

    def __init__(self, user_service):
        self.user_service = user_service

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

        users = self.user_service.list_users(**list_params)
        total = self.user_service.count_users(filtered=False, **list_params)
        filtered = self.user_service.count_users(filtered=True, **list_params)

        response = dict(
            filtered=filtered,
            total=total,
            items=users,
        )

        return response, 200

    def post(self):
        args, errors = schemas.UserRequestSchema().load(request.get_json(force=True))
        if errors:
            raise exceptions.UserParamException.from_errors(errors)
        result = self.user_service.new_user(**args)
        return result, 200


class Plugin(object):

    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['user_service'],)

        api.add_resource(Users, '/users', resource_class_args=args)
        api.add_resource(User, '/users/<string:user_uuid>', resource_class_args=args)
