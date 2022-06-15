# Copyright 2018-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from unittest.mock import Mock, sentinel as s

from hamcrest import assert_that, contains_exactly, empty, equal_to, not_

from ..purpose import Purpose, Purposes


class TestPurpose(unittest.TestCase):
    def test_name(self):
        purpose = Purpose(s.name)
        assert_that(purpose.name, equal_to(s.name))

    def test_default_metadata_plugins(self):
        purpose = Purpose(s.name)
        assert_that(purpose.metadata_plugins, empty())

    def test_metadata_plugins(self):
        plugin = Mock()
        purpose = Purpose(s.name, [plugin])
        assert_that(purpose.metadata_plugins, contains_exactly(plugin))

    def test_add_metadata_plugin(self):
        purpose = Purpose(s.name)
        plugin = Mock()
        purpose.add_metadata_plugin(plugin)
        assert_that(purpose.metadata_plugins, contains_exactly(plugin))

    def test_add_metadata_plugin_twice(self):
        purpose = Purpose(s.name)
        plugin = Mock()
        purpose.add_metadata_plugin(plugin)
        purpose.add_metadata_plugin(plugin)
        assert_that(purpose.metadata_plugins, contains_exactly(plugin))

    def test_eq(self):
        purpose_1 = Purpose(s.name)
        purpose_2 = Purpose(s.name)
        assert_that(purpose_1, equal_to(purpose_2))

    def test_ne(self):
        purpose_1 = Purpose(s.name)
        purpose_2 = Purpose(s.other)
        assert_that(purpose_1, not_(equal_to(purpose_2)))


class TestPurposes(unittest.TestCase):
    def test_configure_plugin_already_configured(self):
        purposes_config = {'user': ['default_user']}
        plugin = Mock()
        metadata_plugins = {'default_user': Mock(obj=plugin)}
        purposes = Purposes(purposes_config, metadata_plugins)
        expected_purpose = Purpose('user', [plugin])

        assert_that(purposes.get('user'), equal_to(expected_purpose))

    def test_get_custom_purpose(self):
        purposes_config = {'custom': []}
        purposes = Purposes(purposes_config, {})

        assert_that(purposes.get('custom'), equal_to(None))

    def test_get_purpose_config(self):
        purposes_config = {'internal': ['test']}
        plugin = Mock()
        metadata_plugins = {'test': Mock(obj=plugin)}
        purposes = Purposes(purposes_config, metadata_plugins)
        expected_purpose = Purpose('internal', [plugin])

        assert_that(purposes.get('internal'), equal_to(expected_purpose))

    def test_get_purpose_config_when_no_loaded(self):
        purposes_config = {'internal': ['test']}
        metadata_plugins = {}
        purposes = Purposes(purposes_config, metadata_plugins)

        assert_that(purposes.get('internal').metadata_plugins, empty())

    def test_get_default(self):
        purposes_config = {}
        plugin = Mock()
        metadata_plugins = {
            'default_user': Mock(obj=plugin),
            'default_internal': Mock(obj=plugin),
            'default_external_api': Mock(obj=plugin),
        }
        purposes = Purposes(purposes_config, metadata_plugins)
        expected_purpose_user = Purpose('user', [plugin])
        expected_purpose_internal = Purpose('internal', [plugin])
        expected_purpose_external_api = Purpose('external_api', [plugin])

        assert_that(purposes.get('user'), equal_to(expected_purpose_user))
        assert_that(purposes.get('internal'), equal_to(expected_purpose_internal))
        assert_that(
            purposes.get('external_api'), equal_to(expected_purpose_external_api)
        )

    def test_get_default_when_no_loaded(self):
        purposes_config = {}
        plugin = Mock()
        metadata_plugins = {}
        purposes = Purposes(purposes_config, metadata_plugins)
        expected_purpose = Purpose('user', [plugin])

        assert_that(purposes.get('user'), not_(expected_purpose))
