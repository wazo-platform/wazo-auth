# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from flask import current_app, request
from wazo_auth import exceptions, http, schemas


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


    def __init__(self, external_auth_service, tenant_service, token_service):
        self.external_auth_service = external_auth_service
        self.tenant_service = tenant_service
        self.token_service = token_service

    @http.required_acl('auth.{auth_type}.external.read')
    def get(self, auth_type):
        tenant_uuid = self._get_tenant_uuid(auth_type)
        response = self.external_auth_service.get_config(auth_type, tenant_uuid=tenant_uuid)
        return {
            'filtered': len(response),
            'items': response,
            'count': len(response)
        }

    @http.required_acl('auth.{auth_type}.external.write')
    def post(self, auth_type):
        data = request.get_json()
        tenant_uuid = self._get_tenant_uuid(auth_type)
        self.external_auth_service.create_config(auth_type, data, tenant_uuid)
        return '', 201

    @http.required_acl('auth.{auth_type}.external.write')
    def put(self, auth_type):
        data = request.get_json()
        tenant_uuid = self._get_tenant_uuid(auth_type)
        self.external_auth_service.update_config(auth_type, data, tenant_uuid)

    @http.required_acl('auth.{auth_type}.external.delete')
    def delete(self, auth_type):
        tenant_uuid = self._get_tenant_uuid(auth_type)
        self.external_auth_service.delete_config(auth_type, tenant_uuid=tenant_uuid)
        return '', 204

    def _get_tenant_uuid(self, auth_type):
        token_tenant_uuid = self.token_service.get(
            request.headers['X-Auth-Token'], 'auth.{auth_type}.external.read'.format(auth_type=auth_type)
        ).metadata.get('tenant_uuid')

        tenant_uuid = request.headers.get('Wazo-Tenant')

        if tenant_uuid:
            self.tenant_service.assert_tenant_under(token_tenant_uuid, tenant_uuid)
            return tenant_uuid
        else:
            return token_tenant_uuid
