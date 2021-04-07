# Copyright 2018-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo_bus.resources.auth import events
from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService


class TenantService(BaseService):
    def __init__(
        self,
        dao,
        tenant_tree,
        group_service,
        policy_service,
        all_users_policies,
        bus_publisher=None,
    ):
        super().__init__(dao, tenant_tree)
        self._bus_publisher = bus_publisher
        self._group_service = group_service
        self._policy_service = policy_service
        self._all_users_policies = all_users_policies

    def assert_tenant_under(self, scoping_tenant_uuid, tenant_uuid):
        visible_tenants = self.list_sub_tenants(scoping_tenant_uuid)
        if str(tenant_uuid) not in visible_tenants:
            raise exceptions.UnknownTenantException(tenant_uuid)

    def count_policies(self, tenant_uuid, scoping_tenant_uuid, **kwargs):
        self.assert_tenant_under(scoping_tenant_uuid, tenant_uuid)
        return self._dao.tenant.count_policies(tenant_uuid, **kwargs)

    def count_users(self, tenant_uuid, **kwargs):
        result = self._dao.tenant.count_users(tenant_uuid, **kwargs)
        if not result and not self._dao.tenant.exists(tenant_uuid):
            raise exceptions.UnknownTenantException(tenant_uuid)

        return result

    def count(self, scoping_tenant_uuid, **kwargs):
        visible_tenants = self.list_sub_tenants(scoping_tenant_uuid)
        return self._dao.tenant.count(tenant_uuids=visible_tenants, **kwargs)

    def delete(self, scoping_tenant_uuid, uuid):
        visible_tenants = self.list_sub_tenants(scoping_tenant_uuid)
        if uuid not in visible_tenants:
            raise exceptions.UnknownTenantException(uuid)

        result = self._dao.tenant.delete(uuid)

        event = events.TenantDeletedEvent(uuid)
        self._bus_publisher.publish(event)
        return result

    def find_top_tenant(self):
        return self._dao.tenant.find_top_tenant()

    def get(self, scoping_tenant_uuid, uuid):
        visible_tenants = self.list_sub_tenants(scoping_tenant_uuid)
        if uuid not in visible_tenants:
            raise exceptions.UnknownTenantException(uuid)

        return self._get(uuid)

    def _get(self, uuid):
        tenants = self._dao.tenant.list_(uuid=uuid, limit=1)
        for tenant in tenants:
            return tenant
        raise exceptions.UnknownTenantException(uuid)

    def list_(self, scoping_tenant_uuid, **kwargs):
        visible_tenants = self.list_sub_tenants(scoping_tenant_uuid)
        return self._dao.tenant.list_(tenant_uuids=visible_tenants, **kwargs)

    def list_policies(self, tenant_uuid, scoping_tenant_uuid, **kwargs):
        self.assert_tenant_under(scoping_tenant_uuid, tenant_uuid)
        return self._dao.policy.list_(tenant_uuid=tenant_uuid, **kwargs)

    def list_users(self, tenant_uuid, **kwargs):
        return self._dao.user.list_(tenant_uuid=tenant_uuid, **kwargs)

    def list_sub_tenants(self, tenant_uuid):
        return self._tenant_tree.list_visible_tenants(tenant_uuid)

    def new(self, **kwargs):
        uuid = self._dao.tenant.create(**kwargs)
        self._dao.address.new(tenant_uuid=uuid, **kwargs['address'])
        result = self._get(uuid)

        event = events.TenantCreatedEvent(
            uuid=uuid,
            name=result['name'],
            slug=result['slug'],
        )
        self._bus_publisher.publish(event)

        all_users_group = self._group_service.create(
            name=f'wazo-all-users-tenant-{uuid}', tenant_uuid=uuid, system_managed=True
        )

        for slug, policy in self._all_users_policies.items():
            all_users_policy_uuid = self._policy_service.create(
                name=slug,
                slug=slug,
                tenant_uuid=uuid,
                description='Automatically created to be applied to all users',
                **policy,
            )
            self._group_service.add_policy(
                all_users_group['uuid'], all_users_policy_uuid
            )

        return result

    def update(self, scoping_tenant_uuid, tenant_uuid, **kwargs):
        visible_tenants = self.list_sub_tenants(scoping_tenant_uuid)
        if tenant_uuid not in visible_tenants:
            raise exceptions.UnknownTenantException(tenant_uuid)

        address_id = self._dao.tenant.get_address_id(tenant_uuid)
        if not address_id:
            address_id = self._dao.address.new(
                tenant_uuid=tenant_uuid, **kwargs['address']
            )
        else:
            address_id, self._dao.address.update(address_id, **kwargs['address'])

        self._dao.tenant.update(tenant_uuid, **kwargs)

        result = self._get(tenant_uuid)
        event = events.TenantUpdatedEvent(tenant_uuid, result.get('name'))
        self._bus_publisher.publish(event)
        return result
