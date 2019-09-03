# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from flask import request
import marshmallow

from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Tenant

from .schemas import ChangePasswordSchema, UserPostSchema, UserPutSchema

logger = logging.getLogger(__name__)


class BaseUserService(http.AuthResource):

    def __init__(self, user_service):
        self.user_service = user_service


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

    @http.required_acl('auth.users.{user_uuid}.edit')
    def put(self, user_uuid):
        scoping_tenant = Tenant.autodetect()
        try:
            args = UserPutSchema().load(request.get_json())
        except marshmallow.ValidationError as e:
            raise exceptions.UserParamException.from_errors(e.messages)

        result = self.user_service.update(scoping_tenant.uuid, user_uuid, **args)
        return result, 200


class UserPassword(BaseUserService):

    @http.required_acl('auth.users.{user_uuid}.password.edit')
    def put(self, user_uuid):
        try:
            args = ChangePasswordSchema().load(request.get_json())
        except marshmallow.ValidationError as e:
            raise exceptions.PasswordChangeException.from_errors(e.messages)
        self.user_service.change_password(user_uuid, **args)
        return '', 204


class Users(BaseUserService):

    def __init__(self, user_service):
        self.user_service = user_service

    @http.required_acl('auth.users.read')
    def get(self):
        scoping_tenant = Tenant.autodetect()
        ListSchema = schemas.new_list_schema('username')
        try:
            list_params = ListSchema().load(request.args)
        except marshmallow.ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        users = self.user_service.list_users(scoping_tenant_uuid=scoping_tenant.uuid, **list_params)
        total = self.user_service.count_users(scoping_tenant.uuid, filtered=False, **list_params)
        filtered = self.user_service.count_users(scoping_tenant.uuid, filtered=True, **list_params)

        response = {
            'filtered': filtered,
            'total': total,
            'items': users,
        }

        return response, 200

    @http.required_acl('auth.users.create')
    def post(self):
        tenant = Tenant.autodetect()
        try:
            args = UserPostSchema().load(request.get_json())
        except marshmallow.ValidationError as e:
            raise exceptions.UserParamException.from_errors(e.messages)
        logger.debug('creating user in tenant: %s', tenant.uuid)
        result = self.user_service.new_user(email_confirmed=True, tenant_uuid=tenant.uuid, **args)
        return result, 200
