# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from flask import request
from wazo_auth import exceptions, http, schemas
from .schemas import ChangePasswordSchema, UserPostSchema


class BaseUserService(http.AuthResource):

    def __init__(self, user_service):
        self.user_service = user_service


class User(BaseUserService):

    @http.required_acl('auth.users.{user_uuid}.read')
    def get(self, user_uuid):
        return self.user_service.get_user(user_uuid)

    @http.required_acl('auth.users.{user_uuid}.delete')
    def delete(self, user_uuid):
        self.user_service.delete_user(user_uuid)
        return '', 204


class UserPassword(BaseUserService):

    @http.required_acl('auth.users.{user_uuid}.password.edit')
    def put(self, user_uuid):
        args, errors = ChangePasswordSchema().load(request.get_json())
        if errors:
            raise exceptions.PasswordChangeException.from_errors(errors)
        self.user_service.change_password(user_uuid, **args)
        return '', 204


class Users(BaseUserService):

    @http.required_acl('auth.users.read')
    def get(self):
        ListSchema = schemas.new_list_schema('username')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        users = self.user_service.list_users(**list_params)
        total = self.user_service.count_users(filtered=False, **list_params)
        filtered = self.user_service.count_users(filtered=True, **list_params)

        response = dict(
            filtered=filtered,
            total=total,
            items=users,
        )

        return response, 200

    @http.required_acl('auth.users.create')
    def post(self):
        args, errors = UserPostSchema().load(request.get_json())
        if errors:
            raise exceptions.UserParamException.from_errors(errors)
        result = self.user_service.new_user(email_confirmed=True, **args)
        return result, 200
