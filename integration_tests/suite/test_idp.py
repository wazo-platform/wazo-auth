# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import assert_that, contains_inanyorder, has_entries

from .helpers import base


@base.use_asset('base')
class TestAuthenticationMethods(base.APIIntegrationTest):
    def test_authentication_backend_list(self):
        response = self.client.idp.list()

        assert_that(
            response,
            has_entries(
                total=4,
                filtered=4,
                items=contains_inanyorder(
                    'ldap',
                    'native',
                    'saml',
                    'default',
                ),
            ),
        )
