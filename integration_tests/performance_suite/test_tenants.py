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

        assert timer.last < 5
        assert result['total'] >= 5000

    # TODO: test tenant creation performance
    # TODO: test subtenant creation performance
    # TODO: detect changes in database after rollback
