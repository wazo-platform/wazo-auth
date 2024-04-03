# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import codetiming

from .helpers import base, fixtures


@base.use_asset('base')
class TestTenants(base.APIIntegrationTest):
    @fixtures.http.bulk_tenants()
    def test_list_all_tenants(self):
        top_tenant = self.get_top_tenant()

        with codetiming.Timer() as timer:
            result = self.client.tenants.list(tenant_uuid=top_tenant['uuid'])

        assert timer.last < 1
        assert result['total'] >= 5000

    @fixtures.http.tenant(name='5k-subtenants-parent')
    @fixtures.http.bulk_tenants(parent_name='5k-subtenants-parent')
    def test_list_all_subtenants(self, parent_tenant):
        with codetiming.Timer() as timer:
            result = self.client.tenants.list(
                tenant_uuid=parent_tenant['uuid'], recurse=True
            )

        assert timer.last < 1
        assert result['total'] >= 5000

    @fixtures.http.bulk_tenants()
    def test_create_tenant(self):
        with codetiming.Timer() as timer:
            tenant = self.client.tenants.new(
                name='performance-tenant-creation', slug='perftc'
            )

        try:
            assert timer.last < 0.1
        finally:
            self.client.tenants.delete(tenant['uuid'])

    @fixtures.http.tenant(name='create-subtenant-parent')
    @fixtures.http.bulk_tenants()
    def test_create_subtenant(self, parent_tenant):
        with codetiming.Timer() as timer:
            tenant = self.client.tenants.new(
                name='performance-tenant-creation',
                parent_uuid=parent_tenant['uuid'],
                slug='perftc',
            )

        try:
            assert timer.last < 0.1
        finally:
            self.client.tenants.delete(tenant['uuid'])
