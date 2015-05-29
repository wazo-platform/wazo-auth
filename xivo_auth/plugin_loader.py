# -*- coding: utf-8 -*-

# Copyright (C) 2015 Avencall
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import logging

from stevedore.dispatch import NameDispatchExtensionManager

logger = logging.getLogger(__name__)


def load_plugins(application, config):
    enabled = config['enabled_plugins']
    backends = NameDispatchExtensionManager(namespace='xivo_auth.backends',
                                            check_func=lambda plugin: plugin.name in enabled,
                                            on_load_failure_callback=plugins_load_fail,
                                            verify_requirements=False,
                                            propagate_map_exceptions=True,
                                            invoke_on_load=False)
    backends.map(enabled, _load_plugin, config)
    return backends


def _load_plugin(extension, config):
    try:
        extension.obj = extension.plugin(config)
    except Exception:
        logger.exception('Failed to load plugin %s', extension.name)


def plugins_load_fail(manager, entrypoint, exception):
    logger.info('Failed to load %s: %s', entrypoint, repr(exception))
