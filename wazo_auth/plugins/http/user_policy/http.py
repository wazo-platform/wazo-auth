# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from flask import request
import marshmallow

from wazo_auth import http, schemas, exceptions
from wazo_auth.plugins.http.policies.schemas import policy_full_schema

logger = logging.getLogger(__name__)


class _BaseUserPolicyResource(http.AuthResource):
    def __init__(self, user_service):
        self.user_service = user_service


class UserPolicies(_BaseUserPolicyResource):
    @http.required_acl('auth.users.{user_uuid}.policies.read')
    def get(self, user_uuid):
        try:
            list_params = schemas.UserPolicyListSchema().load(request.args)
        except marshmallow.ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        policies = self.user_service.list_policies(user_uuid, **list_params)
        items = policy_full_schema.dump(policies, many=True)
        total = self.user_service.count_policies(
            user_uuid, filtered=False, **list_params
        )
        filtered = self.user_service.count_policies(
            user_uuid, filtered=True, **list_params
        )
        return {'items': items, 'total': total, 'filtered': filtered}, 200


class UserPolicy(_BaseUserPolicyResource):
    @http.required_acl('auth.users.{user_uuid}.policies.{policy_uuid}.delete')
    def delete(self, user_uuid, policy_uuid):
        self.user_service.remove_policy(user_uuid, policy_uuid)
        return '', 204

    @http.required_acl('auth.users.{user_uuid}.policies.{policy_uuid}.create')
    def put(self, user_uuid, policy_uuid):
        self.user_service.add_policy(user_uuid, policy_uuid)
        return '', 204
