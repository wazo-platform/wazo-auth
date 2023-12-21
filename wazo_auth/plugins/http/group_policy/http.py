# Copyright 2017-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

import marshmallow
from flask import request
from xivo.auth_verifier import AccessCheck, Unauthorized

from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Token, get_tenant_uuids
from wazo_auth.plugins.http.policies.schemas import policy_full_schema

logger = logging.getLogger(__name__)


class _BaseResource(http.AuthResource):
    def __init__(self, group_service, policy_service):
        self.group_service = group_service
        self.policy_service = policy_service


class _GroupPolicy(_BaseResource):
    def _delete(self, group_uuid, policy_uuid, tenant_uuids):
        tenant_uuids = get_tenant_uuids(recurse=True)
        self.group_service.assert_group_in_subtenant(tenant_uuids, group_uuid)
        # FIXME(fblackburn): Dissociation should be done on the same tenant
        # self.policy_service.assert_policy_in_subtenant(tenant_uuids, policy_uuid)
        self.group_service.remove_policy(group_uuid, policy_uuid)
        return '', 204

    def _put(self, group_uuid, policy_uuid, tenant_uuids):
        tenant_uuids = get_tenant_uuids(recurse=True)

        self.group_service.assert_group_in_subtenant(tenant_uuids, group_uuid)
        # FIXME(fblackburn): Association should be done on the same tenant
        # self.policy_service.assert_policy_in_subtenant(tenant_uuids, policy_uuid)

        token = Token.from_headers()
        access_check = AccessCheck(token.auth_id, token.session_uuid, token.acl)
        policy = self.policy_service.get(policy_uuid, tenant_uuids)
        for access in policy.acl:
            if not access_check.may_add_access(access):
                raise Unauthorized(token.token, required_access=access)

        self.group_service.add_policy(group_uuid, policy_uuid)
        return '', 204


class GroupPolicyUUID(_GroupPolicy):
    @http.required_acl('auth.groups.{group_uuid}.policies.{policy_uuid}.delete')
    def delete(self, group_uuid, policy_uuid):
        tenant_uuids = get_tenant_uuids(recurse=True)
        return super()._delete(group_uuid, policy_uuid, tenant_uuids)

    @http.required_acl('auth.groups.{group_uuid}.policies.{policy_uuid}.create')
    def put(self, group_uuid, policy_uuid):
        tenant_uuids = get_tenant_uuids(recurse=True)
        return super()._put(group_uuid, policy_uuid, tenant_uuids)


class GroupPolicySlug(_GroupPolicy):
    @http.required_acl('auth.groups.{group_uuid}.policies.{policy_slug}.delete')
    def delete(self, group_uuid, policy_slug):
        tenant_uuids = get_tenant_uuids(recurse=False)
        policy = self.policy_service.get_by_slug(policy_slug, tenant_uuids)
        return super()._delete(group_uuid, policy.uuid, tenant_uuids)

    @http.required_acl('auth.groups.{group_uuid}.policies.{policy_slug}.create')
    def put(self, group_uuid, policy_slug):
        tenant_uuids = get_tenant_uuids(recurse=False)
        policy = self.policy_service.get_by_slug(policy_slug, tenant_uuids)
        return super()._put(group_uuid, policy.uuid, tenant_uuids)


class GroupPolicies(_BaseResource):
    @http.required_acl('auth.groups.{group_uuid}.policies.read')
    def get(self, group_uuid):
        tenant_uuids = get_tenant_uuids(recurse=True)

        self.group_service.assert_group_in_subtenant(tenant_uuids, group_uuid)

        try:
            list_params = schemas.GroupPolicyListSchema().load(request.args)
        except marshmallow.ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        policies = self.group_service.list_policies(
            group_uuid,
            tenant_uuids=tenant_uuids,
            **list_params,
        )
        total = self.group_service.count_policies(
            group_uuid,
            filtered=False,
            **list_params,
        )
        filtered = self.group_service.count_policies(
            group_uuid,
            filtered=True,
            **list_params,
        )
        return (
            {
                'items': policy_full_schema.dump(policies, many=True),
                'total': total,
                'filtered': filtered,
            },
            200,
        )
