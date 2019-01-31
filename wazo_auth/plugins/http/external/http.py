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
