# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from flask import request
from xivo.auth_verifier import AccessCheck, Unauthorized
import marshmallow

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
            if not access_check.matches_required_access(access):
                raise Unauthorized(token.token, required_access=access)

        policy = self.policy_service.create(**body)

        return policy_full_schema.dump(policy), 200

    @http.required_acl('auth.policies.read')
    def get(self):
        scoping_tenant = Tenant.autodetect()
        try:
            list_params = schemas.PolicyListSchema().load(request.args)
        except marshmallow.ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        list_params['scoping_tenant_uuid'] = scoping_tenant.uuid

        policies = self.policy_service.list(**list_params)
        total = self.policy_service.count(**list_params)
        items = policy_full_schema.dump(policies, many=True)
        return {'items': items, 'total': total}, 200


class Policy(_BasePolicyRessource):
    @http.required_acl('auth.policies.{policy_uuid}.read')
    def get(self, policy_uuid):
        tenant_uuids = get_tenant_uuids(recurse=True)
        policy = self.policy_service.get(policy_uuid, tenant_uuids)
        return policy_full_schema.dump(policy), 200

    @http.required_acl('auth.policies.{policy_uuid}.delete')
    def delete(self, policy_uuid):
        tenant_uuids = get_tenant_uuids(recurse=True)
        self.policy_service.delete(policy_uuid, tenant_uuids)
        return '', 204

    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def put(self, policy_uuid):
        token = Token.from_headers()
        tenant_uuids = get_tenant_uuids(recurse=True)
        try:
            body = policy_put_schema.load(request.get_json(force=True))
        except marshmallow.ValidationError as e:
            for field in e.messages:
                raise exceptions.InvalidInputException(field)

        access_check = AccessCheck(token.auth_id, token.session_uuid, token.acl)
        for access in body['acl']:
            if not access_check.matches_required_access(access):
                raise Unauthorized(token.token, required_access=access)

        body['tenant_uuids'] = tenant_uuids
        policy = self.policy_service.update(policy_uuid, **body)
        return policy_full_schema.dump(policy), 200


class PolicyAccess(_BasePolicyRessource):
    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def delete(self, policy_uuid, access):
        scoping_tenant = Tenant.autodetect()
        self.policy_service.delete_access(policy_uuid, access, scoping_tenant.uuid)
        return '', 204

    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def put(self, policy_uuid, access):
        token = Token.from_headers()
        scoping_tenant = Tenant.autodetect()

        access_check = AccessCheck(token.auth_id, token.session_uuid, token.acl)
        if not access_check.matches_required_access(access):
            raise Unauthorized(token.token, required_access=access)

        self.policy_service.add_access(policy_uuid, access, scoping_tenant.uuid)
        return '', 204
