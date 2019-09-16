# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from flask import request
import marshmallow
from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Tenant


class _BaseGroupResource(http.AuthResource):

    def __init__(self, group_service):
        self.group_service = group_service


class Group(_BaseGroupResource):

    @http.required_acl('auth.groups.{group_uuid}.delete')
    def delete(self, group_uuid):
        scoping_tenant = Tenant.autodetect()
        self.group_service.delete(group_uuid, scoping_tenant.uuid)
        return '', 204

    @http.required_acl('auth.groups.{group_uuid}.read')
    def get(self, group_uuid):
        scoping_tenant = Tenant.autodetect()
        return self.group_service.get(group_uuid, scoping_tenant.uuid)

    @http.required_acl('auth.groups.{group_uuid}.edit')
    def put(self, group_uuid):
        scoping_tenant = Tenant.autodetect()

        self.group_service.assert_group_in_subtenant(scoping_tenant.uuid, group_uuid)

        try:
            args = schemas.GroupRequestSchema().load(request.get_json())
        except marshmallow.ValidationError as e:
            raise exceptions.GroupParamException.from_errors(e.messages)

        group = self.group_service.update(group_uuid, **args)
        return group, 200


class Groups(_BaseGroupResource):

    @http.required_acl('auth.groups.read')
    def get(self):
        scoping_tenant = Tenant.autodetect()
        ListSchema = schemas.new_list_schema('name')
        try:
            list_params = ListSchema().load(request.args)
        except marshmallow.ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        list_params['scoping_tenant_uuid'] = scoping_tenant.uuid

        groups = self.group_service.list_(**list_params)
        total = self.group_service.count(filtered=False, **list_params)
        filtered = self.group_service.count(filtered=True, **list_params)

        response = {
            'filtered': filtered,
            'total': total,
            'items': groups,
        }

        return response, 200

    @http.required_acl('auth.groups.create')
    def post(self):
        try:
            args = schemas.GroupRequestSchema().load(request.get_json())
        except marshmallow.ValidationError as e:
            raise exceptions.GroupParamException.from_errors(e.messages)

        args['tenant_uuid'] = Tenant.autodetect().uuid
        result = self.group_service.create(**args)
        return result, 200
