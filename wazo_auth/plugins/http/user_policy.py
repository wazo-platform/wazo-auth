# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from flask import request
from wazo_auth import http, schemas, exceptions

logger = logging.getLogger(__name__)


class _BaseUserPolicyResource(http.ErrorCatchingResource):

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

        for key, value in request.args.iteritems():
            if key in list_params:
                continue
            list_params[key] = value

        return {
            'items': self.user_service.list_policies(user_uuid, **list_params),
            'total': self.user_service.count_policies(user_uuid, filtered=False, **list_params),
            'filtered': self.user_service.count_policies(user_uuid, filtered=True, **list_params),
        }, 200


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


class Plugin(object):

    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['user_service'],)

        api.add_resource(
            UserPolicy,
            '/users/<string:user_uuid>/policies/<string:policy_uuid>',
            resource_class_args=args,
        )
        api.add_resource(
            UserPolicies,
            '/users/<string:user_uuid>/policies',
            resource_class_args=args,
        )