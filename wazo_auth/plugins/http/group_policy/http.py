# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from flask import request
from wazo_auth import exceptions, http, schemas

logger = logging.getLogger(__name__)


class _BaseResource(http.AuthResource):

    def __init__(self, group_service):
        self.group_service = group_service


class GroupPolicy(_BaseResource):

    @http.required_acl('auth.groups.{group_uuid}.policies.{policy_uuid}.create')
    def delete(self, group_uuid, policy_uuid):
        logger.debug('disassociating group %s policy %s', group_uuid, policy_uuid)
        self.group_service.remove_policy(group_uuid, policy_uuid)
        return '', 204

    @http.required_acl('auth.groups.{group_uuid}.policies.{policy_uuid}.create')
    def put(self, group_uuid, policy_uuid):
        logger.debug('associating group %s policy %s', group_uuid, policy_uuid)
        self.group_service.add_policy(group_uuid, policy_uuid)
        return '', 204


class GroupPolicies(_BaseResource):

    @http.required_acl('auth.groups.{group_uuid}.policies.read')
    def get(self, group_uuid):
        ListSchema = schemas.new_list_schema('name')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        return {
            'items': self.group_service.list_policies(group_uuid, **list_params),
            'total': self.group_service.count_policies(group_uuid, filtered=False, **list_params),
            'filtered': self.group_service.count_policies(group_uuid, filtered=True, **list_params),
        }, 200
