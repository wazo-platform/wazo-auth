# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from flask import request
import marshmallow
from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Tenant, get_tenant_uuids


class _BaseGroupResource(http.AuthResource):
    def __init__(self, group_service):
        self.group_service = group_service


class Group(_BaseGroupResource):
    @http.required_acl('auth.groups.{group_uuid}.delete')
    def delete(self, group_uuid):
        tenant_uuids = get_tenant_uuids(recurse=True)
        self.group_service.delete(group_uuid, tenant_uuids)
        return '', 204

    @http.required_acl('auth.groups.{group_uuid}.read')
    def get(self, group_uuid):
        tenant_uuids = get_tenant_uuids(recurse=True)
        return self.group_service.get(group_uuid, tenant_uuids)

    @http.required_acl('auth.groups.{group_uuid}.edit')
    def put(self, group_uuid):
        tenant_uuids = get_tenant_uuids(recurse=True)
        try:
            body = schemas.GroupRequestSchema().load(request.get_json())
        except marshmallow.ValidationError as e:
            raise exceptions.GroupParamException.from_errors(e.messages)

        body['tenant_uuids'] = tenant_uuids
        group = self.group_service.update(group_uuid, **body)
        return group, 200


class Groups(_BaseGroupResource):
    @http.required_acl('auth.groups.read')
    def get(self):
        try:
            list_params = schemas.GroupListSchema().load(request.args)
        except marshmallow.ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        recurse = list_params.pop('recurse')
        tenant_uuids = get_tenant_uuids(recurse=recurse)
        groups = self.group_service.list_(tenant_uuids=tenant_uuids, **list_params)
        total = self.group_service.count(
            tenant_uuids=tenant_uuids,
            filtered=False,
            **list_params,
        )
        filtered = self.group_service.count(
            tenant_uuids=tenant_uuids,
            filtered=True,
            **list_params,
        )
        response = {'filtered': filtered, 'total': total, 'items': groups}
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
