# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from flask import request
from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Tenant
from .schemas import PolicySchema


class _BasePolicyRessource(http.AuthResource):

    def __init__(self, policy_service):
        self.policy_service = policy_service


class Policies(_BasePolicyRessource):

    @http.required_acl('auth.policies.create')
    def post(self):
        schema = PolicySchema()
        body, errors = schema.load(request.get_json(force=True))
        if errors:
            for field in errors:
                raise exceptions.InvalidInputException(field)

        body['tenant_uuid'] = Tenant.autodetect().uuid
        body['uuid'] = self.policy_service.create(**body)

        return body, 200

    @http.required_acl('auth.policies.read')
    def get(self):
        scoping_tenant = Tenant.autodetect()
        ListSchema = schemas.new_list_schema('name')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        list_params['scoping_tenant_uuid'] = scoping_tenant.uuid

        policies = self.policy_service.list(**list_params)
        total = self.policy_service.count(**list_params)
        return {'items': policies, 'total': total}, 200


class Policy(_BasePolicyRessource):

    @http.required_acl('auth.policies.{policy_uuid}.read')
    def get(self, policy_uuid):
        scoping_tenant = Tenant.autodetect()
        policy = self.policy_service.get(policy_uuid, scoping_tenant_uuid=scoping_tenant.uuid)
        return policy, 200

    @http.required_acl('auth.policies.{policy_uuid}.delete')
    def delete(self, policy_uuid):
        scoping_tenant = Tenant.autodetect()
        self.policy_service.delete(policy_uuid, scoping_tenant_uuid=scoping_tenant.uuid)
        return '', 204

    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def put(self, policy_uuid):
        scoping_tenant = Tenant.autodetect()
        body, errors = PolicySchema().load(request.get_json(force=True))
        if errors:
            for field in errors:
                raise exceptions.InvalidInputException(field)

        body['scoping_tenant_uuid'] = scoping_tenant.uuid
        policy = self.policy_service.update(policy_uuid, **body)
        return policy, 200


class PolicyTemplate(_BasePolicyRessource):

    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def delete(self, policy_uuid, template):
        self.policy_service.delete_acl_template(policy_uuid, template)
        return '', 204

    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def put(self, policy_uuid, template):
        self.policy_service.add_acl_template(policy_uuid, template)
        return '', 204
