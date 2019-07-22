# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from flask import request

from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Tenant


class Sessions(http.AuthResource):
    def __init__(self, session_service):
        self.session_service = session_service

    @http.required_acl('auth.sessions.read')
    def get(self):
        scoping_tenant = Tenant.autodetect()
        ListSchema = schemas.new_list_schema()
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        list_params['scoping_tenant_uuid'] = scoping_tenant.uuid

        sessions = self.session_service.list_(**list_params)
        total = self.session_service.count(filtered=False, **list_params)
        filtered = self.session_service.count(filtered=True, **list_params)

        response = {'filtered': filtered, 'total': total, 'items': sessions}

        return response, 200


class Session(http.AuthResource):
    def __init__(self, session_service):
        self.session_service = session_service

    @http.required_acl('auth.sessions.{session_uuid}.delete')
    def delete(self, session_uuid):
        scoping_tenant = Tenant.autodetect()
        self.session_service.delete(scoping_tenant.uuid, session_uuid)
        return '', 204
