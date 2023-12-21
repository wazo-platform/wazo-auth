# Copyright 2021-2023 The Wazo Authors  (see the AUTHORS file)
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
        debug_true_config = [
            {
                'op': 'replace',
                'path': '/debug',
                'value': True,
            }
        ]
        debug_false_config = [
            {
                'op': 'replace',
                'path': '/debug',
                'value': False,
            }
        ]

        debug_true_patched_config = self.client.config.patch(debug_true_config)
        debug_true_config = self.client.config.get()
        assert_that(debug_true_config, has_entry('debug', True))
        assert_that(debug_true_patched_config, equal_to(debug_true_config))

        debug_false_patched_config = self.client.config.patch(debug_false_config)
        debug_false_config = self.client.config.get()
        assert_that(debug_false_config, has_entry('debug', False))
        assert_that(debug_false_patched_config, equal_to(debug_false_config))

    def test_restrict_only_top_tenant(self):
        top_tenant_uuid = self.get_top_tenant()['uuid']
        with self.client_in_subtenant(parent_uuid=top_tenant_uuid) as (
            auth,
            _,
            __,
        ):
            assert_http_error(401, auth.config.get)
            assert_http_error(401, auth.config.patch, {})
