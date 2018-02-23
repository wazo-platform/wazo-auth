# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from flask import request
from wazo_auth import exceptions, http, schemas


logger = logging.getLogger(__name__)


class TenantPolicy(http.AuthResource):

    def __init__(self, tenant_service):
        self.tenant_service = tenant_service

    @http.required_acl('auth.tenants.{tenant_uuid}.policies.{policy_uuid}.delete')
    def delete(self, tenant_uuid, policy_uuid):
        logger.debug('dissociating tenant %s policy %s', tenant_uuid, policy_uuid)
        self.tenant_service.remove_policy(tenant_uuid, policy_uuid)
        return '', 204

    @http.required_acl('auth.tenants.{tenant_uuid}.policies.{policy_uuid}.create')
    def put(self, tenant_uuid, policy_uuid):
        logger.debug('associating tenant %s policy %s', tenant_uuid, policy_uuid)
        self.tenant_service.add_policy(tenant_uuid, policy_uuid)
        return '', 204


class TenantPolicies(http.AuthResource):

    def __init__(self, tenant_service):
        self.tenant_service = tenant_service

    @http.required_acl('auth.tenants.{tenant_uuid}.users.read')
    def get(self, tenant_uuid):
        ListSchema = schemas.new_list_schema('name')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        total = self.tenant_service.count_policies(tenant_uuid, filtered=False, **list_params)
        filtered = self.tenant_service.count_policies(tenant_uuid, filtered=True, **list_params)

        return {
            'items': self.tenant_service.list_policies(tenant_uuid, **list_params),
            'total': total,
            'filtered': filtered,
        }, 200


class PolicyTenants(http.AuthResource):

    def __init__(self, policy_service):
        self.policy_service = policy_service

    @http.required_acl('auth.policies.{policy_uuid}.tenants.read')
    def get(self, policy_uuid):
        ListSchema = schemas.new_list_schema('name')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        total = self.policy_service.count_tenants(policy_uuid, filtered=False, **list_params)
        filtered = self.policy_service.count_tenants(policy_uuid, filtered=True, **list_params)

        return {
            'items': self.policy_service.list_tenants(policy_uuid, **list_params),
            'total': total,
            'filtered': filtered,
        }, 200
