# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest import TestCase
from unittest.mock import Mock

from hamcrest import assert_that, contains_exactly, contains_string, empty, is_, not_

from ..plugin import SalesforcePlugin
from .helpers import CONFIG


def _load(section):
    api = Mock()
    SalesforcePlugin().load(
        {
            'api': api,
            'config': {'salesforce': section},
            'external_auth_service': Mock(),
            'user_service': Mock(),
        }
    )
    return api


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
        resource_config = api.add_resource.call_args.kwargs['resource_class_args'][2]
        assert_that(resource_config, not_(contains_string('old-client')))

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
