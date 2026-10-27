# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import tempfile
from unittest import TestCase
from unittest.mock import Mock

import yaml
from hamcrest import (
    assert_that,
    contains_exactly,
    contains_string,
    empty,
    equal_to,
    is_,
    not_,
)

from wazo_auth.config import get_config

from ..plugin import SalesforcePlugin
from .helpers import CONFIG

PACKAGED_CONFIG = os.path.join(
    os.path.dirname(__file__), '../../../../../etc/wazo-auth/config.yml'
)
PLUGIN_LOGGER = 'wazo_auth.plugins.external_auth.salesforce'


def _load(section):
    return _load_config({'salesforce': section})


def _load_config(config):
    api = Mock()
    SalesforcePlugin().load(
        {
            'api': api,
            'config': config,
            'external_auth_service': Mock(),
            'user_service': Mock(),
        }
    )
    return api


def _resource_section(api):
    return api.add_resource.call_args.kwargs['resource_class_args'][2]


class TestLoad(TestCase):
    def test_registers_the_user_route(self):
        api = _load(dict(CONFIG['salesforce']))

        api.add_resource.assert_called_once()
        assert_that(
            api.add_resource.call_args.args[1],
            is_('/users/<uuid:user_uuid>/external/salesforce'),
        )

    def test_app_credentials_in_the_config_file_are_ignored_with_one_warning(self):
        section = dict(
            CONFIG['salesforce'],
            client_id='old-client-id',
            client_secret='old-client-secret',
        )

        with self.assertLogs(
            'wazo_auth.plugins.external_auth.salesforce', level='DEBUG'
        ) as logs:
            api = _load(section)

        api.add_resource.assert_called_once()
        warnings = [r for r in logs.records if r.levelname == 'WARNING']
        assert_that(warnings, contains_exactly(not_(None)))
        message = warnings[0].getMessage()
        assert_that(message, contains_string('/0.1/external/salesforce/config'))
        assert_that(
            [r for r in logs.records if 'old-client-secret' in r.getMessage()],
            is_(empty()),
        )
        assert_that(_resource_section(api), equal_to(CONFIG['salesforce']))

    def test_one_credential_key_alone_also_warns(self):
        section = dict(CONFIG['salesforce'], client_secret='old-client-secret')

        with self.assertLogs(
            'wazo_auth.plugins.external_auth.salesforce', level='WARNING'
        ) as logs:
            _load(section)

        assert_that(logs.records, contains_exactly(not_(None)))

    def test_no_credential_keys_no_warning(self):
        with self.assertNoLogs(
            'wazo_auth.plugins.external_auth.salesforce', level='WARNING'
        ):
            _load(dict(CONFIG['salesforce']))

    def test_the_old_package_file_merged_over_the_packaged_config(self):
        with tempfile.TemporaryDirectory() as directory:
            conf_d = os.path.join(directory, 'conf.d')
            os.mkdir(conf_d)
            with open(PACKAGED_CONFIG) as f:
                packaged = yaml.safe_load(f)
            packaged['extra_config_files'] = conf_d
            main_file = os.path.join(directory, 'config.yml')
            with open(main_file, 'w') as f:
                yaml.safe_dump(packaged, f)
            old_package_file = {
                'enabled_external_auth_plugins': {'salesforce': True},
                'salesforce': {
                    'client_id': 'old-client-id',
                    'client_secret': 'old-client-secret',
                },
            }
            with open(os.path.join(conf_d, '050-wazo-salesforce-plugin.yml'), 'w') as f:
                yaml.safe_dump(old_package_file, f)
            config = get_config(['-c', main_file])

        with self.assertLogs(PLUGIN_LOGGER, level='WARNING') as logs:
            api = _load_config(config)

        assert_that(logs.records, contains_exactly(not_(None)))
        assert_that(_resource_section(api), equal_to(packaged['salesforce']))


class TestAccessTokenLifetime(TestCase):
    def lifetime_loaded(self, value):
        api = _load(dict(CONFIG['salesforce'], access_token_lifetime=value))
        return _resource_section(api)['access_token_lifetime']

    def test_a_number_as_text_is_read_as_seconds(self):
        assert_that(self.lifetime_loaded('3600'), equal_to(3600))

    def test_an_unusable_lifetime_falls_back_to_two_hours_with_a_warning(self):
        for value in ('soon', None, 30, 0, -5):
            with self.assertLogs(PLUGIN_LOGGER, level='WARNING') as logs:
                lifetime = self.lifetime_loaded(value)

            assert_that(lifetime, equal_to(7200), value)
            assert_that(logs.output[0], contains_string('access_token_lifetime'), value)
