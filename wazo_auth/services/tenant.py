# Copyright 2018-2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

import psycopg2.errorcodes
import sqlalchemy.exc
from wazo_bus.resources.auth.events import (
    TenantCreatedEvent,
    TenantDeletedEvent,
    TenantUpdatedEvent,
)

from wazo_auth import exceptions
from wazo_auth.services.helpers import BaseService

logger = logging.getLogger(__name__)


class TenantService(BaseService):
    def __init__(
        self,
        dao,
        all_users_policies,
        default_group_service,
        bus_publisher=None,
    ):
        super().__init__(dao)
        self._bus_publisher = bus_publisher
        self._all_users_policies = all_users_policies
        self._default_group_service = default_group_service

    def count(self, scoping_tenant_uuid, **kwargs):
        return self._dao.tenant.count(
            self.top_tenant_uuid, scoping_tenant_uuid, **kwargs
        )

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
        visible_tenants = self._dao.tenant.list_visible_tenants(scoping_tenant_uuid)
        for tenant in visible_tenants:
            if tenant.uuid == id_ or tenant.slug == id_:
                return self._get(tenant.uuid)

        raise exceptions.UnknownTenantException(id_)

    def _get(self, tenant_uuid):
        tenants = self._dao.tenant.list_(
            self.top_tenant_uuid, uuid=tenant_uuid, limit=1
        )
        for tenant in tenants:
            return tenant
        raise exceptions.UnknownTenantException(tenant_uuid)

    def list_(self, scoping_tenant_uuid, **kwargs):
        return self._dao.tenant.list_(
            self.top_tenant_uuid, scoping_tenant_uuid, **kwargs
        )

    def list_sub_tenants(self, tenant_uuid):
        visible_tenants = self._dao.tenant.list_visible_tenants(tenant_uuid)
        return [tenant.uuid for tenant in visible_tenants]

    def new(self, **kwargs):
        try:
            uuid = self._dao.tenant.create(**kwargs)
        except sqlalchemy.exc.IntegrityError as e:
            logger.debug(
                'integrity error(code=%s, pgcode=%s): %s', e.code, e.orig.pgcode, e
            )
            if (
                e.orig.pgcode == psycopg2.errorcodes.UNIQUE_VIOLATION
                and 'Key (uuid)' in str(e)
            ):
                assert 'uuid' in kwargs, 'uuid conflict but no uuid specified?'
                raise exceptions.TenantIdentityConflictException(
                    'uuid',
                    kwargs['uuid'],
                )
            raise e

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

        self._default_group_service.create_groups_for_new_tenant(uuid)

        return result

    def is_subtenant(self, child_uuid, parent_uuid):
        result = self._dao.tenant.is_subtenant(child_uuid, parent_uuid)
        logger.debug(
            'Is tenant %s subtenant of %s? %s', child_uuid, parent_uuid, result
        )
        return result

    def update(self, scoping_tenant_uuid, tenant_uuid, **kwargs):
        visible_tenants = self.list_sub_tenants(scoping_tenant_uuid)
        if str(tenant_uuid) not in visible_tenants:
            raise exceptions.UnknownTenantException(tenant_uuid)

        address_id = self._dao.tenant.get_address_id(tenant_uuid)
        if not address_id:
            self._dao.address.new(tenant_uuid=tenant_uuid, **kwargs['address'])
        else:
            self._dao.address.update(address_id, **kwargs['address'])

        self._dao.tenant.update(tenant_uuid, **kwargs)
        result = self._get(tenant_uuid)
        event = TenantUpdatedEvent(result.get('name'), tenant_uuid)
        self._bus_publisher.publish(event)
        return result

    def list_domains(self, tenant_uuid):
        if self.get(tenant_uuid, tenant_uuid) is None:
            raise exceptions.UnknownTenantException(tenant_uuid)

        domains = self._dao.domain.get(str(tenant_uuid))
        return [{'name': domain.name, 'uuid': domain.uuid} for domain in domains]

    def update_parent(self, scoping_tenant_uuid, tenant_uuid, parent_tenant_uuid):
        if not self._dao.tenant.is_subtenant(
            str(tenant_uuid), str(scoping_tenant_uuid)
        ):
            raise exceptions.UnknownTenantException(tenant_uuid)

        if not self._dao.tenant.is_subtenant(
            str(parent_tenant_uuid), str(scoping_tenant_uuid)
        ):
            raise exceptions.UnknownTenantException(parent_tenant_uuid)

        if self._dao.tenant.is_subtenant(str(parent_tenant_uuid), str(tenant_uuid)):
            raise exceptions.DescendentTenantException(tenant_uuid, parent_tenant_uuid)

        self._dao.tenant.update_parent(str(tenant_uuid), str(parent_tenant_uuid))
