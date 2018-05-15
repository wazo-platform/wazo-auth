# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from flask import request
from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Tenant

logger = logging.getLogger(__name__)


class _BaseResource(http.AuthResource):

    def __init__(self, group_service, user_service):
        self.group_service = group_service
        self.user_service = user_service


class GroupUser(_BaseResource):

    @http.required_acl('auth.groups.{group_uuid}.users.{user_uuid}.delete')
    def delete(self, group_uuid, user_uuid):
        scoping_tenant = Tenant.autodetect()

        self.group_service.assert_group_in_subtenant(scoping_tenant.uuid, group_uuid)

        logger.debug('disassociating group %s user %s', group_uuid, user_uuid)
        self.group_service.remove_user(group_uuid, user_uuid)
        return '', 204

    @http.required_acl('auth.groups.{group_uuid}.users.{user_uuid}.create')
    def put(self, group_uuid, user_uuid):
        scoping_tenant = Tenant.autodetect()

        self.user_service.assert_user_in_subtenant(scoping_tenant.uuid, user_uuid)
        self.group_service.assert_group_in_subtenant(scoping_tenant.uuid, group_uuid)

        logger.debug('associating group %s user %s', group_uuid, user_uuid)
        self.group_service.add_user(group_uuid, user_uuid)
        return '', 204


class GroupUsers(_BaseResource):

    @http.required_acl('auth.groups.{group_uuid}.users.read')
    def get(self, group_uuid):
        ListSchema = schemas.new_list_schema('username')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        return {
            'items': self.group_service.list_users(group_uuid, **list_params),
            'total': self.group_service.count_users(group_uuid, filtered=False, **list_params),
            'filtered': self.group_service.count_users(group_uuid, filtered=True, **list_params),
        }, 200


class UserGroups(http.AuthResource):

    def __init__(self, user_service):
        self.user_service = user_service

    @http.required_acl('auth.users.{user_uuid}.groups.read')
    def get(self, user_uuid):
        ListSchema = schemas.new_list_schema('name')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        return {
            'items': self.user_service.list_groups(user_uuid, **list_params),
            'total': self.user_service.count_groups(user_uuid, filtered=False, **list_params),
            'filtered': self.user_service.count_groups(user_uuid, filtered=True, **list_params),
        }, 200
