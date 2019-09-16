# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from flask import request
import marshmallow

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
        try:
            body = schema.load(request.get_json(force=True))
        except marshmallow.ValidationError as e:
            for field in e.messages:
                raise exceptions.InvalidInputException(field)

        body['tenant_uuid'] = Tenant.autodetect().uuid
        body['uuid'] = self.policy_service.create(**body)

        return body, 200

    @http.required_acl('auth.policies.read')
    def get(self):
        scoping_tenant = Tenant.autodetect()
        ListSchema = schemas.new_list_schema('name')
        try:
            list_params = ListSchema().load(request.args)
        except marshmallow.ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        list_params['scoping_tenant_uuid'] = scoping_tenant.uuid

        policies = self.policy_service.list(**list_params)
        total = self.policy_service.count(**list_params)
        return {'items': policies, 'total': total}, 200


class Policy(_BasePolicyRessource):

    @http.required_acl('auth.policies.{policy_uuid}.read')
    def get(self, policy_uuid):
        scoping_tenant = Tenant.autodetect()
        policy = self.policy_service.get(policy_uuid, scoping_tenant.uuid)
        return policy, 200

    @http.required_acl('auth.policies.{policy_uuid}.delete')
    def delete(self, policy_uuid):
        scoping_tenant = Tenant.autodetect()
        self.policy_service.delete(policy_uuid, scoping_tenant.uuid)
        return '', 204

    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def put(self, policy_uuid):
        scoping_tenant = Tenant.autodetect()
        try:
            body = PolicySchema().load(request.get_json(force=True))
        except marshmallow.ValidationError as e:
            for field in e.messages:
                raise exceptions.InvalidInputException(field)

        body['scoping_tenant_uuid'] = scoping_tenant.uuid
        policy = self.policy_service.update(policy_uuid, **body)
        return policy, 200


class PolicyTemplate(_BasePolicyRessource):

    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def delete(self, policy_uuid, template):
        scoping_tenant = Tenant.autodetect()
        self.policy_service.delete_acl_template(policy_uuid, template, scoping_tenant.uuid)
        return '', 204

    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def put(self, policy_uuid, template):
        scoping_tenant = Tenant.autodetect()
        self.policy_service.add_acl_template(policy_uuid, template, scoping_tenant.uuid)
        return '', 204
