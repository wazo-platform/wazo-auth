# Copyright 2017-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import marshmallow
from flask import current_app, request

from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Tenant


class External(http.AuthResource):
    def __init__(self, external_auth_service):
        self.external_auth_service = external_auth_service

    @http.required_acl('auth.users.{user_uuid}.external.read')
    def get(self, user_uuid):
        try:
            list_params = schemas.ExternalListSchema().load(request.args)
        except marshmallow.ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        items = self.external_auth_service.list_(user_uuid, **list_params)
        total = self.external_auth_service.count(
            user_uuid, filtered=False, **list_params
        )
        filtered = self.external_auth_service.count(
            user_uuid, filtered=True, **list_params
        )

        for item in items:
            plugin_info = current_app.config['external_auth_plugin_info'][item['type']]
            item['plugin_info'] = plugin_info

        response = {'filtered': filtered, 'total': total, 'items': items}

        return response, 200


class ExternalConfig(http.AuthResource):
    def __init__(self, external_auth_service):
        self.external_auth_service = external_auth_service

    @http.required_acl('auth.{auth_type}.external.config.read')
    def get(self, auth_type):
        tenant_uuid = Tenant.autodetect().uuid
        response = self.external_auth_service.get_config(
            auth_type, tenant_uuid=tenant_uuid
        )
        return response

    @http.required_acl('auth.{auth_type}.external.config.create')
    def post(self, auth_type):
        data = request.get_json()
        tenant_uuid = Tenant.autodetect().uuid
        self.external_auth_service.create_config(auth_type, data, tenant_uuid)
        return '', 201

    @http.required_acl('auth.{auth_type}.external.config.update')
    def put(self, auth_type):
        data = request.get_json()
        tenant_uuid = Tenant.autodetect().uuid
        self.external_auth_service.update_config(auth_type, data, tenant_uuid)
        return '', 204

    @http.required_acl('auth.{auth_type}.external.config.delete')
    def delete(self, auth_type):
        tenant_uuid = Tenant.autodetect().uuid
        self.external_auth_service.delete_config(auth_type, tenant_uuid=tenant_uuid)
        return '', 204


class ExternalUsers(http.AuthResource):
    def __init__(self, external_auth_service):
        self.service = external_auth_service

    @http.required_acl('auth.{auth_type}.external.users.read')
    def get(self, auth_type):
        try:
            list_params = schemas.BaseListSchema().load(request.args)
        except marshmallow.ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        tenant_uuid = Tenant.autodetect().uuid

        users = self.service.list_connected_users(auth_type, tenant_uuid, **list_params)
        total = self.service.count_connected_users(
            auth_type, tenant_uuid, **list_params
        )

        response = {
            'filtered': total,
            'total': total,
            'items': [{'uuid': user} for user in users],
        }
        return response, 200
