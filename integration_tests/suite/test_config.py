# Copyright 2021-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import assert_that, equal_to, has_entry, has_key

from .helpers import base
from .helpers.base import assert_http_error


@base.use_asset('base')
class TestConfig(base.APIIntegrationTest):
    def test_config(self):
        result = self.client.config.get()

        assert_that(result, has_key('rest_api'))

    def test_update_config(self):
        previous_value = self.client.config.get()['debug']
        patch_data = [
            {
                'op': 'replace',
                'path': '/debug',
                'value': not previous_value,
            },
        ]

        patched_config = self.client.config.patch(patch_data)
        config = self.client.config.get()
        assert_that(config, has_entry('debug', not previous_value))
        assert_that(patched_config, equal_to(config))

        patch_data[0]['value'] = previous_value
        patched_config = self.client.config.patch(patch_data)
        config = self.client.config.get()
        assert_that(config, has_entry('debug', previous_value))
        assert_that(patched_config, equal_to(config))

    def test_restrict_only_top_tenant(self):
        top_tenant_uuid = self.get_top_tenant()['uuid']
        with self.client_in_subtenant(parent_uuid=top_tenant_uuid) as (
            auth,
            _,
            __,
        ):
            assert_http_error(401, auth.config.get)
            assert_http_error(401, auth.config.patch, {})
