# Copyright 2018-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService


class GroupService(BaseService):
    def add_policy(self, group_uuid, policy_uuid):
        return self._dao.group.add_policy(group_uuid, policy_uuid)

    def add_user(self, group_uuid, user_uuid):
        if self._dao.group.is_system_managed(group_uuid):
            raise exceptions.SystemGroupForbidden(group_uuid)

        return self._dao.group.add_user(group_uuid, user_uuid)

    def count(self, **kwargs):
        return self._dao.group.count(**kwargs)

    def count_policies(self, group_uuid, **kwargs):
        return self._dao.group.count_policies(group_uuid, **kwargs)

    def count_users(self, group_uuid, **kwargs):
        return self._dao.group.count_users(group_uuid, **kwargs)

    def create(self, **kwargs):
        kwargs.setdefault('system_managed', False)
        uuid = self._dao.group.create(**kwargs)
        return {'uuid': uuid, 'read_only': kwargs['system_managed'], **kwargs}

    def delete(self, group_uuid, tenant_uuids):
        if self._dao.group.is_system_managed(group_uuid, tenant_uuids):
            raise exceptions.SystemGroupForbidden(group_uuid)
        return self._dao.group.delete(group_uuid, tenant_uuids=tenant_uuids)

    def get(self, group_uuid, tenant_uuids):
        args = {
            'uuid': group_uuid,
            'limit': 1,
            'tenant_uuids': tenant_uuids,
        }

        matching_groups = self._dao.group.list_(**args)
        for group in matching_groups:
            return group

        raise exceptions.UnknownGroupException(group_uuid)

    def get_acl(self, user_uuid):
        users = self._dao.user.list_(uuid=user_uuid, limit=1)
        acl = []
        for user in users:
            groups = self._dao.group.list_(user_uuid=user['uuid'])
            for group in groups:
                policies = self.list_policies(group['uuid'])
                for policy in policies:
                    acl.extend(policy.acl)
        return acl

    def list_(self, **kwargs):
        return self._dao.group.list_(**kwargs)

    def list_policies(self, group_uuid, **kwargs):
        return self._dao.policy.list_(group_uuid=group_uuid, **kwargs)

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
        if self._dao.group.is_system_managed(group_uuid):
            raise exceptions.SystemGroupForbidden(group_uuid)

        nb_deleted = self._dao.group.remove_user(group_uuid, user_uuid)
        if nb_deleted:
            return

        if not self._dao.group.exists(group_uuid):
            raise exceptions.UnknownGroupException(group_uuid)

        if not self._dao.user.exists(user_uuid):
            raise exceptions.UnknownUserException(user_uuid)

    def update(self, group_uuid, **kwargs):
        if self._dao.group.is_system_managed(group_uuid):
            raise exceptions.SystemGroupForbidden(group_uuid)
        return self._dao.group.update(group_uuid, **kwargs)

    def assert_group_in_subtenant(self, tenant_uuids, uuid):
        exists = self._dao.group.exists(uuid, tenant_uuids=tenant_uuids)
        if not exists:
            raise exceptions.UnknownGroupException(uuid)
