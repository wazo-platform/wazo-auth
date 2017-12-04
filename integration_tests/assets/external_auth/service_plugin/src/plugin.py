# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from flask import request
from wazo_auth import http


class Foo(http.AuthResource):

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
        return self.external_auth_service.create(user_uuid, self.auth_type, data), 200

    @http.required_acl('auth.users.{user_uuid}.external.foo.edit')
    def put(self, user_uuid):
        data = request.get_json(force=True)
        return self.external_auth_service.update(user_uuid, self.auth_type, data), 200


class Plugin(object):

    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['external_auth_service'],)

        api.add_resource(Foo, '/users/<uuid:user_uuid>/external/foo', resource_class_args=args)
