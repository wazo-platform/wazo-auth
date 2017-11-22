# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from flask import request
from wazo_auth import exceptions, http, schemas


class _BaseGroupResource(http.ErrorCatchingResource):

    def __init__(self, group_service):
        self.group_service = group_service


class Group(_BaseGroupResource):

    @http.required_acl('auth.groups.{group_uuid}.delete')
    def delete(self, group_uuid):
        self.group_service.delete(group_uuid)
        return '', 204

    @http.required_acl('auth.groups.{group_uuid}.read')
    def get(self, group_uuid):
        return self.group_service.get(group_uuid)

    @http.required_acl('auth.groups.{group_uuid}.edit')
    def put(self, group_uuid):
        args, errors = schemas.GroupRequestSchema().load(request.get_json())
        if errors:
            raise exceptions.GroupParamException.from_errors(errors)

        group = self.group_service.update(group_uuid, **args)
        return group, 200


class Groups(_BaseGroupResource):

    @http.required_acl('auth.groups.read')
    def get(self):
        ListSchema = schemas.new_list_schema('name')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        for key, value in request.args.iteritems():
            if key in list_params:
                continue
            list_params[key] = value

        groups = self.group_service.list_(**list_params)
        total = self.group_service.count(filtered=False, **list_params)
        filtered = self.group_service.count(filtered=True, **list_params)

        response = dict(
            filtered=filtered,
            total=total,
            items=groups,
        )

        return response, 200

    @http.required_acl('auth.groups.create')
    def post(self):
        args, errors = schemas.GroupRequestSchema().load(request.get_json())
        if errors:
            raise exceptions.GroupParamException.from_errors(errors)
        result = self.group_service.create(**args)
        return result, 200
