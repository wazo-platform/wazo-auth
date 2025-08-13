# Copyright 2019-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

import marshmallow
from flask import request

from wazo_auth import exceptions, http
from wazo_auth.flask_helpers import Tenant
from wazo_auth.services.external_auth import ExternalAuthService
from wazo_auth.services.user import UserService

from .schemas import MobileSchema

logger = logging.getLogger(__name__)


class MobileAuthSenderID(http.AuthResource):
    auth_type = 'mobile'

    def __init__(
        self, external_auth_service: ExternalAuthService, user_service: UserService
    ):
        self.external_auth_service = external_auth_service
        self.user_service = user_service

    @http.required_acl('auth.users.{user_uuid}.external.mobile.sender_id.read')
    def get(self, user_uuid):
        tenant = Tenant.autodetect()
        config = self.external_auth_service.get_config(self.auth_type, tenant.uuid)
        return {"sender_id": config.get('fcm_sender_id')}, 200


class MobileAuth(http.AuthResource):
    auth_type = 'mobile'

    def __init__(self, external_auth_service: ExternalAuthService):
        self.external_auth_service = external_auth_service

    @http.required_acl('auth.users.{user_uuid}.external.mobile.delete')
    def delete(self, user_uuid):
        self.external_auth_service.delete(user_uuid, self.auth_type)
        return '', 204

    @http.required_acl('auth.users.{user_uuid}.external.mobile.read')
    def get(self, user_uuid):
        data = self.external_auth_service.get(user_uuid, self.auth_type)
        return MobileSchema().dump(data)

    @http.required_acl('auth.users.{user_uuid}.external.mobile.create')
    def post(self, user_uuid):
        try:
            args = MobileSchema().load(request.get_json())
        except marshmallow.ValidationError as e:
            raise exceptions.UserParamException.from_errors(e.messages)

        logger.info(
            'Tokens registered for User(%s) in plugin external mobile', str(user_uuid)
        )
        self.external_auth_service.create(user_uuid, self.auth_type, args)
        return args, 201

    @http.required_acl('auth.users.{user_uuid}.external.mobile.update')
    def put(self, user_uuid):
        try:
            args = MobileSchema().load(request.get_json())
        except marshmallow.ValidationError as e:
            raise exceptions.UserParamException.from_errors(e.messages)

        self.external_auth_service.update(user_uuid, self.auth_type, args)
        return args, 200
