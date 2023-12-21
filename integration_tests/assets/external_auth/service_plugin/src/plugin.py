# Copyright 2017-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import random
import string

from flask import request
from marshmallow import Schema, fields, pre_load

from wazo_auth import http

logger = logging.getLogger(__name__)


def new_state():
    return ''.join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(16)
    )


class FooService(http.AuthResource):
    auth_type = 'foo'
    states = {}

    def __init__(self, external_auth_service):
        self.external_auth_service = external_auth_service

    @http.required_acl('auth.users.{user_uuid}.external.foo.delete')
    def delete(self, user_uuid):
        self.external_auth_service.delete(user_uuid, self.auth_type)
        return '', 204

    @http.required_acl('auth.users.{user_uuid}.external.foo.read')
    def get(self, user_uuid):
        return self.external_auth_service.get(user_uuid, self.auth_type), 200

    @http.required_acl('auth.users.{user_uuid}.external.foo.create')
    def post(self, user_uuid):
        state = self.states[user_uuid] = new_state()
        data = request.get_json(force=True)
        data['state'] = state
        self.external_auth_service.register_oauth2_callback(
            self.auth_type, user_uuid, state, self.create_first_token, user_uuid
        )
        return self.external_auth_service.create(user_uuid, self.auth_type, data), 200

    @http.required_acl('auth.users.{user_uuid}.external.foo.edit')
    def put(self, user_uuid):
        data = request.get_json(force=True)
        return self.external_auth_service.update(user_uuid, self.auth_type, data), 200

    def create_first_token(self, user_uuid, msg):
        logger.debug('received the oauth2 callback %s %s', user_uuid, msg)
        data = self.external_auth_service.get(user_uuid, self.auth_type)
        data['access_token'] = msg['access_token']
        self.external_auth_service.update(user_uuid, self.auth_type, data)
        logger.debug('callback done')


class BarService(http.AuthResource):
    auth_type = 'bar'

    def __init__(self, external_auth_service):
        self.external_auth_service = external_auth_service

    @http.required_acl('auth.users.{user_uuid}.external.bar.delete')
    def delete(self, user_uuid):
        self.external_auth_service.delete(user_uuid, self.auth_type)
        return '', 204

    @http.required_acl('auth.users.{user_uuid}.external.bar.read')
    def get(self, user_uuid):
        return self.external_auth_service.get(user_uuid, self.auth_type), 200

    @http.required_acl('auth.users.{user_uuid}.external.bar.create')
    def post(self, user_uuid):
        data = request.get_json(force=True)
        return self.external_auth_service.create(user_uuid, self.auth_type, data), 200

    @http.required_acl('auth.users.{user_uuid}.external.bar.edit')
    def put(self, user_uuid):
        data = request.get_json(force=True)
        return self.external_auth_service.update(user_uuid, self.auth_type, data), 200


class BarSafeData(Schema):
    scope = fields.List(fields.String)

    @pre_load
    def ensure_dict(self, data, **kwargs):
        return data or {}


class BarPlugin:
    plugin_info = {'foo': 'bar'}

    def load(self, dependencies):
        api = dependencies['api']
        external_auth_service = dependencies['external_auth_service']
        args = (external_auth_service,)
        external_auth_service.register_safe_auth_model('bar', BarSafeData)

        api.add_resource(
            BarService, '/users/<uuid:user_uuid>/external/bar', resource_class_args=args
        )


class FooPlugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['external_auth_service'],)

        api.add_resource(
            FooService, '/users/<uuid:user_uuid>/external/foo', resource_class_args=args
        )
