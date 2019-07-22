# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from flask import request
from wazo_auth import http, schemas, exceptions

logger = logging.getLogger(__name__)


class _BaseUserPolicyResource(http.AuthResource):
    def __init__(self, user_service):
        self.user_service = user_service


class UserPolicies(_BaseUserPolicyResource):
    @http.required_acl('auth.users.{user_uuid}.policies.read')
    def get(self, user_uuid):
        logger.debug('listing user %s policies', user_uuid)
        ListSchema = schemas.new_list_schema('name')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        return (
            {
                'items': self.user_service.list_policies(user_uuid, **list_params),
                'total': self.user_service.count_policies(
                    user_uuid, filtered=False, **list_params
                ),
                'filtered': self.user_service.count_policies(
                    user_uuid, filtered=True, **list_params
                ),
            },
            200,
        )


class UserPolicy(_BaseUserPolicyResource):
    @http.required_acl('auth.users.{user_uuid}.policies.{policy_uuid}.delete')
    def delete(self, user_uuid, policy_uuid):
        logger.debug('disassociating user %s and policy %s', user_uuid, policy_uuid)
        self.user_service.remove_policy(user_uuid, policy_uuid)
        return '', 204

    @http.required_acl('auth.users.{user_uuid}.policies.{policy_uuid}.create')
    def put(self, user_uuid, policy_uuid):
        logger.debug('associating user %s and policy %s', user_uuid, policy_uuid)
        self.user_service.add_policy(user_uuid, policy_uuid)
        return '', 204
