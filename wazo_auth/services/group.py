# Copyright 2018-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService


class GroupService(BaseService):
    def add_policy(self, group_uuid, policy_uuid):
        return self._dao.group.add_policy(group_uuid, policy_uuid)

    def add_user(self, group_uuid, user_uuid):
        return self._dao.group.add_user(group_uuid, user_uuid)

    def count(self, scoping_tenant_uuid, recurse=False, **kwargs):
        if scoping_tenant_uuid:
            kwargs['tenant_uuids'] = self._get_scoped_tenant_uuids(
                scoping_tenant_uuid, recurse
            )
        return self._dao.group.count(**kwargs)

    def count_policies(self, group_uuid, **kwargs):
        return self._dao.group.count_policies(group_uuid, **kwargs)

    def count_users(self, group_uuid, **kwargs):
        return self._dao.group.count_users(group_uuid, **kwargs)

    def create(self, **kwargs):
        kwargs.setdefault('system_managed', False)
        uuid = self._dao.group.create(**kwargs)
        return dict(uuid=uuid, **kwargs)

    def delete(self, group_uuid, scoping_tenant_uuid):
        tenant_uuids = self._tenant_tree.list_visible_tenants(scoping_tenant_uuid)
        return self._dao.group.delete(group_uuid, tenant_uuids=tenant_uuids)

    def get(self, group_uuid, scoping_tenant_uuid):
        args = {
            'uuid': group_uuid,
            'limit': 1,
            'tenant_uuids': self._tenant_tree.list_visible_tenants(scoping_tenant_uuid),
        }

        matching_groups = self._dao.group.list_(**args)
        for group in matching_groups:
            return group

        raise exceptions.UnknownGroupException(group_uuid)

    def get_all_users_group(self, tenant_uuid):
        args = {
            'name': f'wazo-all-users-tenant-{tenant_uuid}',
            'limit': 1,
            'tenant_uuids': [tenant_uuid],
        }

        matching_groups = self._dao.group.list_(**args)
        for group in matching_groups:
            return group

    def get_acl_templates(self, username):
        users = self._dao.user.list_(username=username, limit=1)
        acl_templates = []
        for user in users:
            groups = self._dao.group.list_(user_uuid=user['uuid'])
            for group in groups:
                policies = self.list_policies(group['uuid'])
                for policy in policies:
                    acl_templates.extend(policy['acl_templates'])
        return acl_templates

    def list_(self, scoping_tenant_uuid=None, recurse=False, **kwargs):
        if scoping_tenant_uuid:
            kwargs['tenant_uuids'] = self._get_scoped_tenant_uuids(
                scoping_tenant_uuid, recurse
            )

        return self._dao.group.list_(**kwargs)

    def list_policies(self, group_uuid, **kwargs):
        return self._dao.policy.get(group_uuid=group_uuid, **kwargs)

    def list_users(self, group_uuid, **kwargs):
        return self._dao.user.list_(group_uuid=group_uuid, **kwargs)

    def remove_policy(self, group_uuid, policy_uuid):
        nb_deleted = self._dao.group.remove_policy(group_uuid, policy_uuid)
        if nb_deleted:
            return

        if not self._dao.group.exists(group_uuid):
            raise exceptions.UnknownGroupException(group_uuid)

        if not self._dao.policy.exists(policy_uuid):
            raise exceptions.UnknownPolicyException(policy_uuid)

    def remove_user(self, group_uuid, user_uuid):
        nb_deleted = self._dao.group.remove_user(group_uuid, user_uuid)
        if nb_deleted:
            return

        if not self._dao.group.exists(group_uuid):
            raise exceptions.UnknownGroupException(group_uuid)

        if not self._dao.user.exists(user_uuid):
            raise exceptions.UnknownUserException(user_uuid)

    def update(self, group_uuid, **kwargs):
        return self._dao.group.update(group_uuid, **kwargs)

    def assert_group_in_subtenant(self, scoping_tenant_uuid, uuid):
        tenant_uuids = self._tenant_tree.list_visible_tenants(scoping_tenant_uuid)
        exists = self._dao.group.exists(uuid, tenant_uuids=tenant_uuids)
        if not exists:
            raise exceptions.UnknownGroupException(uuid)
