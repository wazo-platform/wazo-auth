# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from xivo_bus.resources.auth import events
from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService, TenantTree


class TenantService(BaseService):

    def __init__(self, dao, bus_publisher=None):
        super(TenantService, self).__init__(dao)
        self._bus_publisher = bus_publisher

    def add_policy(self, tenant_uuid, policy_uuid):
        return self._dao.tenant.add_policy(tenant_uuid, policy_uuid)

    def count_policies(self, tenant_uuid, **kwargs):
        return self._dao.tenant.count_policies(tenant_uuid, **kwargs)

    def count_users(self, tenant_uuid, **kwargs):
        return self._dao.tenant.count_users(tenant_uuid, **kwargs)

    def count(self, top_tenant_uuid, **kwargs):
        visible_tenants = self.list_sub_tenants(top_tenant_uuid)
        return self._dao.tenant.count(tenant_uuids=visible_tenants, **kwargs)

    def delete(self, top_tenant_uuid, uuid):
        visible_tenants = self.list_sub_tenants(top_tenant_uuid)
        if uuid not in visible_tenants:
            raise exceptions.UnknownTenantException(uuid)

        result = self._dao.tenant.delete(uuid)
        event = events.TenantDeletedEvent(uuid)
        self._bus_publisher.publish(event)
        return result

    def find_top_tenant(self):
        return self._dao.tenant.find_top_tenant()

    def get(self, top_tenant_uuid, uuid):
        visible_tenants = self.list_sub_tenants(top_tenant_uuid)
        if uuid not in visible_tenants:
            raise exceptions.UnknownTenantException(uuid)

        return self._get(uuid)

    def _get(self, uuid):
        tenants = self._dao.tenant.list_(uuid=uuid, limit=1)
        for tenant in tenants:
            return tenant
        raise exceptions.UnknownTenantException(uuid)

    def list_(self, top_tenant_uuid, **kwargs):
        visible_tenants = self.list_sub_tenants(top_tenant_uuid)
        return self._dao.tenant.list_(tenant_uuids=visible_tenants, **kwargs)

    def list_policies(self, tenant_uuid, **kwargs):
        return self._dao.policy.list_(tenant_uuid=tenant_uuid, **kwargs)

    def list_users(self, tenant_uuid, **kwargs):
        return self._dao.user.list_(tenant_uuid=tenant_uuid, **kwargs)

    def list_sub_tenants(self, tenant_uuid):
        # TODO the tenant_tree instance could be stored globaly and rebuild when adding/deleting tenants
        all_tenants = self._dao.tenant.list_()
        tenant_tree = TenantTree(all_tenants)
        return tenant_tree.list_nodes(tenant_uuid)

    def new(self, **kwargs):
        address_id = self._dao.address.new(**kwargs['address'])
        uuid = self._dao.tenant.create(address_id=address_id, **kwargs)
        result = self._get(uuid)
        event = events.TenantCreatedEvent(uuid, kwargs.get('name'))
        self._bus_publisher.publish(event)
        return result

    def remove_policy(self, tenant_uuid, policy_uuid):
        nb_deleted = self._dao.tenant.remove_policy(tenant_uuid, policy_uuid)
        if nb_deleted:
            return

        if not self._dao.tenant.exists(tenant_uuid):
            raise exceptions.UnknownTenantException(tenant_uuid)

        if not self._dao.policy.exists(policy_uuid):
            raise exceptions.UnknownPolicyException(policy_uuid)

    def update(self, top_tenant_uuid, tenant_uuid, **kwargs):
        visible_tenants = self.list_sub_tenants(top_tenant_uuid)
        if tenant_uuid not in visible_tenants:
            raise exceptions.UnknownTenantException(tenant_uuid)

        address_id = self._dao.tenant.get_address_id(tenant_uuid)
        if not address_id:
            address_id = self._dao.address.new(**kwargs['address'])
        else:
            address_id, self._dao.address.update(address_id, **kwargs['address'])

        self._dao.tenant.update(tenant_uuid, address_id=address_id, **kwargs)

        result = self._get(tenant_uuid)
        event = events.TenantUpdatedEvent(tenant_uuid, result.get('name'))
        self._bus_publisher.publish(event)
        return result
