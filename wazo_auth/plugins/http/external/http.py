# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from flask import current_app, request
from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Tenant


class External(http.AuthResource):

    def __init__(self, external_auth_service):
        self.external_auth_service = external_auth_service

    @http.required_acl('auth.users.{user_uuid}.external.read')
    def get(self, user_uuid):
        ListSchema = schemas.new_list_schema('type')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        items = self.external_auth_service.list_(user_uuid, **list_params)
        total = self.external_auth_service.count(user_uuid, filtered=False, **list_params)
        filtered = self.external_auth_service.count(user_uuid, filtered=True, **list_params)

        for item in items:
            plugin_info = current_app.config['external_auth_plugin_info'][item['type']]
            item['plugin_info'] = plugin_info

        response = {
            'filtered': filtered,
            'total': total,
            'items': items,
        }

        return response, 200


class ExternalConfig(http.AuthResource):


    def __init__(self, external_auth_service):
        self.external_auth_service = external_auth_service

    @http.required_acl('auth.{auth_type}.external.read')
    def get(self, auth_type):
        tenant_uuid = Tenant.autodetect().uuid
        response = self.external_auth_service.get_config(auth_type, tenant_uuid=tenant_uuid)
        return {
            'filtered': len(response),
            'items': response,
            'count': len(response)
        }, 200

    @http.required_acl('auth.{auth_type}.external.write')
    def post(self, auth_type):
        data = request.get_json()
        tenant_uuid = Tenant.autodetect().uuid
        self.external_auth_service.create_config(auth_type, data, tenant_uuid)
        return '', 201

    @http.required_acl('auth.{auth_type}.external.write')
    def put(self, auth_type):
        data = request.get_json()
        tenant_uuid = Tenant.autodetect().uuid
        self.external_auth_service.update_config(auth_type, data, tenant_uuid)
        return '', 204

    @http.required_acl('auth.{auth_type}.external.delete')
    def delete(self, auth_type):
        tenant_uuid = Tenant.autodetect().uuid
        self.external_auth_service.delete_config(auth_type, tenant_uuid=tenant_uuid)
        return '', 204

