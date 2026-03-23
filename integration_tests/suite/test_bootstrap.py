# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import yaml

from .helpers import base

CLI_CONFIG_PATH = '/root/.config/wazo-auth-cli/050-credentials.yml'


@base.use_asset('bootstrap')
class TestBootstrapComplete(base.BootstrapIntegrationTest):
    def setUp(self):
        self._run_bootstrap_complete()

    def _run_bootstrap_complete(self):
        self.asset_cls.docker_exec(['wazo-auth-bootstrap', 'complete'], 'auth')

    def _read_cli_config(self):
        content = self.asset_cls.docker_exec(['cat', CLI_CONFIG_PATH], 'auth').decode(
            'utf-8'
        )
        return yaml.safe_load(content)

    def test_complete_is_idempotent(self):
        config_before = self._read_cli_config()

        self._run_bootstrap_complete()

        config_after = self._read_cli_config()
        assert config_before == config_after

    def test_complete_resets_password_when_config_file_is_missing(self):
        self.asset_cls.docker_exec(['rm', CLI_CONFIG_PATH], 'auth')

        self._run_bootstrap_complete()

        config = self._read_cli_config()
        username = config['auth']['username']
        password = config['auth']['password']
        client = self.make_auth_client(username, password)
        token = client.token.new(expiration=60)
        assert token['token']
        client.token.revoke(token['token'])
