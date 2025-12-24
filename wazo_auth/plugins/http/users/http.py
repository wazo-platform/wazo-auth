# Copyright 2017-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

import marshmallow
from flask import request

from wazo_auth import exceptions, http
from wazo_auth.flask_helpers import Tenant
from wazo_auth.schemas import UserListSchema

from .schemas import ChangePasswordSchema, UserPostSchema, UserPutSchema

logger = logging.getLogger(__name__)


user_post_schema = UserPostSchema()
user_put_schema = UserPutSchema()
change_password_schema = ChangePasswordSchema()
user_list_schema = UserListSchema()


class BaseUserService(http.AuthResource):
    def __init__(self, user_service, idp_service):
        self.user_service = user_service
        self.idp_service = idp_service


class User(BaseUserService):
    @http.required_acl('auth.users.{user_uuid}.read')
    def get(self, user_uuid):
        scoping_tenant = Tenant.autodetect()
        return self.user_service.get_user(user_uuid, scoping_tenant.uuid)

    @http.required_acl('auth.users.{user_uuid}.delete')
    def delete(self, user_uuid):
        scoping_tenant = Tenant.autodetect()
        self.user_service.delete_user(scoping_tenant.uuid, user_uuid)
        return '', 204

    @http.required_acl('auth.users.{user_uuid}.update')
    def put(self, user_uuid):
        scoping_tenant = Tenant.autodetect()
        try:
            args = user_put_schema.load(request.get_json(force=True))
        except marshmallow.ValidationError as e:
            raise exceptions.UserParamException.from_errors(e.messages)

        if not self.idp_service.is_valid_idp_type(args['authentication_method']):
            raise exceptions.UserParamException(
                f'Invalid authentication method {args["authentication_method"]}',
                details={'authentication_method': args['authentication_method']},
            )

        result = self.user_service.update(scoping_tenant.uuid, user_uuid, **args)
        return result, 200


class UserPassword(BaseUserService):
    @http.required_acl('auth.users.{user_uuid}.password.update')
    def put(self, user_uuid):
        try:
            args = change_password_schema.load(request.get_json(force=True))
        except marshmallow.ValidationError as e:
            raise exceptions.PasswordChangeException.from_errors(e.messages)
        self.user_service.change_password(user_uuid, **args)
        return '', 204


class Users(BaseUserService):
    @http.required_acl('auth.users.read')
    def get(self):
        scoping_tenant = Tenant.autodetect()
        try:
            list_params = user_list_schema.load(request.args)
        except marshmallow.ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        users = self.user_service.list_users(
            scoping_tenant_uuid=scoping_tenant.uuid, **list_params
        )
        total = self.user_service.count_users(
            scoping_tenant.uuid, filtered=False, **list_params
        )
        filtered = self.user_service.count_users(
            scoping_tenant.uuid, filtered=True, **list_params
        )

        response = {'filtered': filtered, 'total': total, 'items': users}

        return response, 200

    @http.required_acl('auth.users.create')
    def post(self):
        tenant = Tenant.autodetect()
        try:
            args = user_post_schema.load(request.get_json(force=True))
        except marshmallow.ValidationError as e:
            raise exceptions.UserParamException.from_errors(e.messages)

        if not self.idp_service.is_valid_idp_type(args['authentication_method']):
            raise exceptions.UserParamException(
                f'Invalid authentication method {args["authentication_method"]}',
                details={'authentication_method': args['authentication_method']},
            )

        logger.debug('creating user in tenant: %s', tenant.uuid)
        result = self.user_service.new_user(
            email_confirmed=True, tenant_uuid=tenant.uuid, **args
        )
        return result, 200
