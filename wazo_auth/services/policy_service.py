# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService


class PolicyService(BaseService):

    def add_acl_template(self, policy_uuid, acl_template):
        return self._dao.policy.associate_policy_template(policy_uuid, acl_template)

    def create(self, **kwargs):
        return self._dao.policy.create(**kwargs)

    def count(self, **kwargs):
        return self._dao.policy.count(**kwargs)

    def delete(self, policy_uuid):
        return self._dao.policy.delete(policy_uuid)

    def delete_acl_template(self, policy_uuid, acl_template):
        nb_deleted = self._dao.policy.dissociate_policy_template(policy_uuid, acl_template)
        if nb_deleted:
            return

        if not self._dao.policy.exists(policy_uuid):
            raise exceptions.UnknownPolicyException(policy_uuid)

    def get(self, policy_uuid):
        matching_policies = self._dao.policy.get(uuid=policy_uuid)
        for policy in matching_policies:
            return policy
        raise exceptions.UnknownPolicyException(policy_uuid)

    def list(self, **kwargs):
        return self._dao.policy.get(**kwargs)

    def update(self, policy_uuid, **body):
        self._dao.policy.update(policy_uuid, **body)
        return dict(uuid=policy_uuid, **body)
