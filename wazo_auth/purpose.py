# Copyright 2018-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

logger = logging.getLogger()


class Purpose:
    def __init__(self, name, metadata_plugins=None):
        self.name = name
        metadata_plugins = metadata_plugins or []
        self._metadata_plugins = list(metadata_plugins)

    @property
    def metadata_plugins(self):
        return list(self._metadata_plugins)

    def add_metadata_plugin(self, metadata_plugin):
        if metadata_plugin not in self._metadata_plugins:
            self._metadata_plugins.append(metadata_plugin)

    def __eq__(self, other):
        return (
            self.name == other.name
            and self._metadata_plugins == other._metadata_plugins
        )

    def __ne__(self, other):
        return not self == other


class Purposes:

    valid_purposes = [
        'user',
        'internal',
        'external_api',
        'tenant_admin',
    ]

    default_metadata_plugins = {
        'user': 'default_user',
        'internal': 'default_internal',
        'external_api': 'default_external_api',
        'tenant_admin': 'default_tenant_admin',
    }

    def __init__(self, purposes_config, metadata_plugins):
        self._metadata_plugins = metadata_plugins
        self._purposes = {purpose: Purpose(purpose) for purpose in self.valid_purposes}

        self._add_default_metadata_plugins()
        self._add_metadata_plugins(purposes_config)

    def _add_default_metadata_plugins(self):
        for purpose_name, plugin_name in self.default_metadata_plugins.items():
            purpose = self._purposes.get(purpose_name)
            if not purpose:
                continue
            try:
                plugin = self._metadata_plugins[plugin_name]
            except KeyError:
                logger.warning(
                    "Purposes must have the following metadata plugins enabled: %s",
                    plugin_name,
                )
                continue
            purpose.add_metadata_plugin(plugin.obj)

    def _add_metadata_plugins(self, purposes_config):
        for purpose_name, plugin_names in purposes_config.items():
            purpose = self._purposes.get(purpose_name)
            if not purpose:
                logger.warning('Configuration has undefined purpose: %s', purpose_name)
                continue

            for plugin_name in plugin_names:
                try:
                    plugin = self._metadata_plugins[plugin_name]
                except KeyError:
                    logger.warning(
                        "A purpose has been assigned to an invalid metadata plugin: %s",
                        plugin_name,
                    )
                    continue
                purpose.add_metadata_plugin(plugin.obj)

    def get(self, name):
        return self._purposes.get(name)
