# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from marshmallow import Schema, fields, pre_load
from flask import request
from wazo_auth import http


class FooService(http.AuthResource):

    auth_type = 'foo'

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
        data = request.get_json(force=True)
        self.external_auth_service.register_oauth2_callback(self.create_first_token, user_uuid)
        return self.external_auth_service.create(user_uuid, self.auth_type, data), 200

    @http.required_acl('auth.users.{user_uuid}.external.foo.edit')
    def put(self, user_uuid):
        data = request.get_json(force=True)
        return self.external_auth_service.update(user_uuid, self.auth_type, data), 200

    def create_first_token(self, user_uuid, msg):
        data = self.external_auth_service.get(user_uuid, self.auth_type)
        data['access_token'] = msg['access_token']
        self.external_auth_service.update(user_uuid, self.auth_type, data)


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
    def ensure_dict(self, data):
        return data or {}


class BarPlugin(object):

    plugin_info = {'foo': 'bar'}

    def load(self, dependencies):
        api = dependencies['api']
        external_auth_service = dependencies['external_auth_service']
        args = (external_auth_service,)
        external_auth_service.register_safe_auth_model('bar', BarSafeData)

        api.add_resource(BarService, '/users/<uuid:user_uuid>/external/bar', resource_class_args=args)


class FooPlugin(object):

    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['external_auth_service'],)

        api.add_resource(FooService, '/users/<uuid:user_uuid>/external/foo', resource_class_args=args)
