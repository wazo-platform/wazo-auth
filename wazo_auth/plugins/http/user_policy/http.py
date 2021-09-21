# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from flask import request
from xivo.auth_verifier import AccessCheck, Unauthorized
import marshmallow

from wazo_auth import http, schemas, exceptions
from wazo_auth.flask_helpers import Token, get_tenant_uuids
from wazo_auth.plugins.http.policies.schemas import policy_full_schema

logger = logging.getLogger(__name__)


class _BaseUserPolicyResource(http.AuthResource):
    def __init__(self, user_service, policy_service):
        self.user_service = user_service
        self.policy_service = policy_service


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


class _UserPolicy(_BaseUserPolicyResource):
    def _delete(self, user_uuid, policy_uuid, tenant_uuids):
        # FIXME(fblackburn): Currently not multi-tenant
        # self.policy_service.assert_user_in_subtenant(tenant_uuids, policy_uuid)
        # FIXME(fblackburn): Dissociation should be done on the same tenant
        # self.policy_service.assert_policy_in_subtenant(tenant_uuids, policy_uuid)
        self.user_service.remove_policy(user_uuid, policy_uuid)
        return '', 204

    def _put(self, user_uuid, policy_uuid, tenant_uuids):
        token = Token.from_headers()

        # FIXME(fblackburn): Currently not multi-tenant
        # self.policy_service.assert_user_in_subtenant(tenant_uuids, policy_uuid)
        # FIXME(fblackburn): Association should be done on the same tenant
        # self.policy_service.assert_policy_in_subtenant(tenant_uuids, policy_uuid)

        access_check = AccessCheck(token.auth_id, token.session_uuid, token.acl)
        # FIXME(fblackburn): Policy should be accessible by the tenant
        # policy = self.policy_service.get(policy_uuid, tenant_uuids)
        policy = self.policy_service.get(policy_uuid, tenant_uuids=None)
        for access in policy.acl:
            if not access_check.may_add_access(access):
                raise Unauthorized(token.token, required_access=access)

        self.user_service.add_policy(user_uuid, policy_uuid)
        return '', 204


class UserPolicyUUID(_UserPolicy):
    @http.required_acl('auth.users.{user_uuid}.policies.{policy_uuid}.delete')
    def delete(self, user_uuid, policy_uuid):
        tenant_uuids = get_tenant_uuids(recurse=True)
        return super()._delete(user_uuid, policy_uuid, tenant_uuids)

    @http.required_acl('auth.users.{user_uuid}.policies.{policy_uuid}.create')
    def put(self, user_uuid, policy_uuid):
        tenant_uuids = get_tenant_uuids(recurse=True)
        return super()._put(user_uuid, policy_uuid, tenant_uuids)


class UserPolicySlug(_UserPolicy):
    @http.required_acl('auth.users.{user_uuid}.policies.{policy_slug}.delete')
    def delete(self, user_uuid, policy_slug):
        tenant_uuids = get_tenant_uuids(recurse=False)
        policy = self.policy_service.get_by_slug(policy_slug, tenant_uuids)
        return super()._delete(user_uuid, policy.uuid, tenant_uuids)

    @http.required_acl('auth.users.{user_uuid}.policies.{policy_slug}.create')
    def put(self, user_uuid, policy_slug):
        tenant_uuids = get_tenant_uuids(recurse=False)
        policy = self.policy_service.get_by_slug(policy_slug, tenant_uuids)
        return super()._put(user_uuid, policy.uuid, tenant_uuids)
