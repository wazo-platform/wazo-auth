# Copyright 2018-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo_bus.resources.auth.events import (
    TenantCreatedEvent,
    TenantDeletedEvent,
    TenantUpdatedEvent,
)

from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService


class TenantService(BaseService):
    def __init__(
        self,
        dao,
        tenant_tree,
        all_users_policies,
        default_group_service,
        bus_publisher=None,
    ):
        super().__init__(dao, tenant_tree)
        self._bus_publisher = bus_publisher
        self._all_users_policies = all_users_policies
        self._default_group_service = default_group_service

    def assert_tenant_under(self, scoping_tenant_uuid, tenant_uuid):
        visible_tenants = self.list_sub_tenants(scoping_tenant_uuid)
        if str(tenant_uuid) not in visible_tenants:
            raise exceptions.UnknownTenantException(tenant_uuid)

    def count(self, scoping_tenant_uuid, **kwargs):
        visible_tenants = self.list_sub_tenants(scoping_tenant_uuid)
        return self._dao.tenant.count(tenant_uuids=visible_tenants, **kwargs)

    def delete(self, scoping_tenant_uuid, tenant_uuid):
        visible_tenants = self.list_sub_tenants(scoping_tenant_uuid)
        if str(tenant_uuid) not in visible_tenants:
            raise exceptions.UnknownTenantException(tenant_uuid)

        result = self._dao.tenant.delete(tenant_uuid)

        event = TenantDeletedEvent(tenant_uuid)
        self._bus_publisher.publish(event)
        return result

    def find_top_tenant(self):
        return self.top_tenant_uuid

    def get(self, scoping_tenant_uuid, tenant_uuid):
        visible_tenants = self.list_sub_tenants(scoping_tenant_uuid)
        if str(tenant_uuid) not in visible_tenants:
            raise exceptions.UnknownTenantException(tenant_uuid)

        return self._get(tenant_uuid)

    def get_by_uuid_or_slug(self, scoping_tenant_uuid, id_):
        visible_tenants = self._tenant_tree.list_visible_tenant_uuids_with_slugs(
            scoping_tenant_uuid
        )
        for tenant_uuid, tenant_slug in visible_tenants:
            if tenant_uuid == id_ or tenant_slug == id_:
                return self._get(tenant_uuid)

        raise exceptions.UnknownTenantException(id_)

    def _get(self, tenant_uuid):
        tenants = self._dao.tenant.list_(uuid=tenant_uuid, limit=1)
        for tenant in tenants:
            return tenant
        raise exceptions.UnknownTenantException(tenant_uuid)

    def list_(self, scoping_tenant_uuid, **kwargs):
        visible_tenants = self.list_sub_tenants(scoping_tenant_uuid)
        return self._dao.tenant.list_(tenant_uuids=visible_tenants, **kwargs)

    def list_sub_tenants(self, tenant_uuid):
        return self._tenant_tree.list_visible_tenants(tenant_uuid)

    def new(self, **kwargs):
        uuid = self._dao.tenant.create(**kwargs)
        self._dao.address.new(tenant_uuid=uuid, **kwargs['address'])
        result = self._get(uuid)

        event = TenantCreatedEvent(
            {
                'uuid': uuid,
                'name': result['name'],
                'slug': result['slug'],
                'domain_names': result['domain_names'],
            },
            uuid,
        )
        self._bus_publisher.publish(event)

        name = f'wazo-all-users-tenant-{uuid}'
        all_users_group_uuid = self._dao.group.create(
            name=name,
            slug=name,
            tenant_uuid=uuid,
            system_managed=True,
        )

        for slug, enabled in self._all_users_policies.items():
            if not enabled:
                continue

            all_users_policy = self._dao.policy.find_by(slug=slug)
            if not all_users_policy:
                raise Exception('All users policy %s not found')
            self._dao.group.add_policy(all_users_group_uuid, all_users_policy.uuid)

        self._default_group_service.update_groups_for_tenant(uuid)

        return result

    def update(self, scoping_tenant_uuid, tenant_uuid, **kwargs):
        visible_tenants = self.list_sub_tenants(scoping_tenant_uuid)
        if str(tenant_uuid) not in visible_tenants:
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
        event = TenantUpdatedEvent(result.get('name'), tenant_uuid)
        self._bus_publisher.publish(event)
        return result
