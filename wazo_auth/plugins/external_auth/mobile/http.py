# -*- coding: utf-8 -*-
# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from flask import request

from xivo.mallow import fields
from wazo_auth import exceptions, http, schemas

logger = logging.getLogger(__name__)


class MobilePostSchema(schemas.BaseSchema):

    token = fields.String(min=1, max=512)
    apns_token = fields.String(allow_none=True)


class MobileAuthSenderID(http.AuthResource):

    auth_type = 'mobile'

    def __init__(self, external_auth_service, user_service):
        self.external_auth_service = external_auth_service
        self.user_service = user_service

    @http.required_acl('auth.users.{user_uuid}.external.mobile.read')
    def get(self, user_uuid):
        user = self.user_service.get_user(user_uuid)
        config = self.external_auth_service.get_config(self.auth_type,
                                                       user['tenant_uuid'])
        return {"sender_id": config.get('fcm_sender_id')}, 200


class MobileAuth(http.AuthResource):

    auth_type = 'mobile'

    def __init__(self, external_auth_service, config):
        self.external_auth_service = external_auth_service
        self.config = config

    @http.required_acl('auth.users.{user_uuid}.external.mobile.delete')
    def delete(self, user_uuid):
        self.external_auth_service.delete(user_uuid, self.auth_type)
        return '', 204

    @http.required_acl('auth.users.{user_uuid}.external.mobile.read')
    def get(self, user_uuid):
        data = self.external_auth_service.get(user_uuid, self.auth_type)
        return self._new_get_response(data)

    @http.required_acl('auth.users.{user_uuid}.external.mobile.create')
    def post(self, user_uuid):
        args, errors = MobilePostSchema().load(request.get_json())
        if errors:
            raise exceptions.UserParamException.from_errors(errors)

        logger.info('Token created for User(%s) in plugin external mobile', str(user_uuid))
        data = {
            'token': args.get('token'),
            'apns_token': args.get('apns_token')
        }
        self.external_auth_service.create(user_uuid, self.auth_type, data)
        return data, 201

    @staticmethod
    def _new_get_response(data):
        return {
            'token': data.get('token'),
            'apns_token': data.get('apns_token')
        }, 200
