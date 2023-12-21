# Copyright 2017-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import marshmallow
from flask import request
from xivo.auth_verifier import AccessCheck, Unauthorized

from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Tenant, Token, get_tenant_uuids

from .schemas import policy_full_schema, policy_put_schema


class _BasePolicyRessource(http.AuthResource):
    def __init__(self, policy_service):
        self.policy_service = policy_service


class Policies(_BasePolicyRessource):
    @http.required_acl('auth.policies.create')
    def post(self):
        token = Token.from_headers()
        try:
            body = policy_full_schema.load(request.get_json(force=True))
        except marshmallow.ValidationError as e:
            for field in e.messages:
                raise exceptions.InvalidInputException(field)

        body['tenant_uuid'] = Tenant.autodetect().uuid

        access_check = AccessCheck(token.auth_id, token.session_uuid, token.acl)
        for access in body['acl']:
            if not access_check.may_add_access(access):
                raise Unauthorized(token.token, required_access=access)

        policy = self.policy_service.create(**body)

        return policy_full_schema.dump(policy), 200

    @http.required_acl('auth.policies.read')
    def get(self):
        try:
            list_params = schemas.PolicyListSchema().load(request.args)
        except marshmallow.ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        recurse = list_params.pop('recurse')
        tenant_uuids = get_tenant_uuids(recurse=recurse)
        policies = self.policy_service.list(tenant_uuids=tenant_uuids, **list_params)
        total = self.policy_service.count(tenant_uuids=tenant_uuids, **list_params)
        items = policy_full_schema.dump(policies, many=True)
        return {'items': items, 'total': total}, 200


class _Policy(_BasePolicyRessource):
    def _get(self, policy_uuid, tenant_uuids):
        policy = self.policy_service.get(policy_uuid, tenant_uuids)
        return policy_full_schema.dump(policy), 200

    def _delete(self, policy_uuid, tenant_uuids):
        self.policy_service.delete(policy_uuid, tenant_uuids)
        return '', 204

    def _put(self, policy_uuid, tenant_uuids):
        token = Token.from_headers()
        try:
            body = policy_put_schema.load(request.get_json(force=True))
        except marshmallow.ValidationError as e:
            for field in e.messages:
                raise exceptions.InvalidInputException(field)

        access_check = AccessCheck(token.auth_id, token.session_uuid, token.acl)
        for access in body['acl']:
            if not access_check.may_add_access(access):
                raise Unauthorized(token.token, required_access=access)

        body['tenant_uuids'] = tenant_uuids
        policy = self.policy_service.update(policy_uuid, **body)
        return policy_full_schema.dump(policy), 200


class PolicyUUID(_Policy):
    @http.required_acl('auth.policies.{policy_uuid}.read')
    def get(self, policy_uuid):
        tenant_uuids = get_tenant_uuids(recurse=True)
        return super()._get(policy_uuid, tenant_uuids)

    @http.required_acl('auth.policies.{policy_uuid}.delete')
    def delete(self, policy_uuid):
        tenant_uuids = get_tenant_uuids(recurse=True)
        return super()._delete(policy_uuid, tenant_uuids)

    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def put(self, policy_uuid):
        tenant_uuids = get_tenant_uuids(recurse=True)
        return super()._put(policy_uuid, tenant_uuids)


class PolicySlug(_Policy):
    @http.required_acl('auth.policies.{policy_slug}.read')
    def get(self, policy_slug):
        tenant_uuids = get_tenant_uuids(recurse=False)
        policy = self.policy_service.get_by_slug(policy_slug, tenant_uuids)
        return super()._get(policy.uuid, tenant_uuids)

    @http.required_acl('auth.policies.{policy_slug}.delete')
    def delete(self, policy_slug):
        tenant_uuids = get_tenant_uuids(recurse=False)
        policy = self.policy_service.get_by_slug(policy_slug, tenant_uuids)
        return super()._delete(policy.uuid, tenant_uuids)

    @http.required_acl('auth.policies.{policy_slug}.edit')
    def put(self, policy_slug):
        tenant_uuids = get_tenant_uuids(recurse=False)
        policy = self.policy_service.get_by_slug(policy_slug, tenant_uuids)
        return super()._put(policy.uuid, tenant_uuids)


class _PolicyAccess(_BasePolicyRessource):
    def _delete(self, policy_uuid, access, tenant_uuids):
        self.policy_service.delete_access(policy_uuid, access, tenant_uuids)
        return '', 204

    def _put(self, policy_uuid, access, tenant_uuids):
        token = Token.from_headers()
        access_check = AccessCheck(token.auth_id, token.session_uuid, token.acl)
        if not access_check.may_add_access(access):
            raise Unauthorized(token.token, required_access=access)

        self.policy_service.add_access(policy_uuid, access, tenant_uuids)
        return '', 204


class PolicyUUIDAccess(_PolicyAccess):
    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def delete(self, policy_uuid, access):
        tenant_uuids = get_tenant_uuids(recurse=True)
        return super()._delete(policy_uuid, access, tenant_uuids)

    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def put(self, policy_uuid, access):
        tenant_uuids = get_tenant_uuids(recurse=True)
        return super()._put(policy_uuid, access, tenant_uuids)


class PolicySlugAccess(_PolicyAccess):
    @http.required_acl('auth.policies.{policy_slug}.edit')
    def delete(self, policy_slug, access):
        tenant_uuids = get_tenant_uuids(recurse=False)
        policy = self.policy_service.get_by_slug(policy_slug, tenant_uuids)
        return super()._delete(policy.uuid, access, tenant_uuids)

    @http.required_acl('auth.policies.{policy_slug}.edit')
    def put(self, policy_slug, access):
        tenant_uuids = get_tenant_uuids(recurse=False)
        policy = self.policy_service.get_by_slug(policy_slug, tenant_uuids)
        return super()._put(policy.uuid, access, tenant_uuids)
