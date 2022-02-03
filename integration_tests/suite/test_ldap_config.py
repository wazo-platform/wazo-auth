# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from .helpers import base
from .helpers import fixtures


@base.use_asset('ldap')
class TestLDAPConfigAuth(base.APIIntegrationTest):
    def test_getting_config_with_no_token_returns_401(self):
        pass

    def test_getting_config_with_no_token_no_config_returns_401(self):
        pass

    def test_getting_config_with_token_wrong_tenant_returns_401(self):
        pass

    def test_getting_config_with_token_wrong_tenant_no_config_returns_401(self):
        pass

    def test_getting_config_with_token_with_config_returns_config(self):
        pass
