# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from wazo_auth import http


logger = logging.getLogger(__name__)


class TenantPolicy(http.AuthResource):

    def __init__(self, tenant_service):
        self.tenant_service = tenant_service

    @http.required_acl('auth.tenants.{tenant_uuid}.policies.{policy_uuid}.delete')
    def delete(self, tenant_uuid, policy_uuid):
        logger.debug('dissociating tenant %s policy %s', tenant_uuid, policy_uuid)
        return '', 204

    @http.required_acl('auth.tenants.{tenant_uuid}.policies.{policy_uuid}.create')
    def put(self, tenant_uuid, policy_uuid):
        logger.debug('associating tenant %s policy %s', tenant_uuid, policy_uuid)
        return '', 204


class TenantPolicies(http.AuthResource):

    def __init__(self, tenant_service):
        self.tenant_service = tenant_service

    @http.required_acl('auth.tenants.{tenant_uuid}.users.read')
    def get(self, tenant_uuid):
        return {
            'items': [],
            'total': 0,
            'filtered': 0,
        }, 200


class PolicyTenants(http.AuthResource):

    def __init__(self, policy_service):
        self.user_service = policy_service

    @http.required_acl('auth.policies.{policy_uuid}.tenants.read')
    def get(self, policy_uuid):
        return {
            'items': [],
            'total': 0,
            'filtered': 0,
        }, 200
