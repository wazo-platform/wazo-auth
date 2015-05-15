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

from stevedore.dispatch import NameDispatchExtensionManager


def load_plugins(application):
    plugins = NameDispatchExtensionManager(namespace='xivo_auth.plugins',
                                           check_func=check_plugin,
                                           on_load_failure_callback=plugins_load_fail,
                                           verify_requirements=True,
                                           propagate_map_exceptions=True,
                                           invoke_on_load=True)

    plugs = application.config['plugins']
    plugins.map(plugs, launch_plugin, application)


def check_plugin(plugin):
    return True


def launch_plugin(ext, application):
    print "Loading dynamic plugin : %s" % ext.name
    ext.obj.load(application)


def plugins_load_fail(manager, entrypoint, exception):
    print "There is an error with this module: ", manager
    print "The entry point is: ", entrypoint
    print "The exception is: ", exception
