# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Avencall
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

import abc


class BaseAuthenticationBackend(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self, config):
        """Initialize this backend instance from the given configuration"""

    def get_consul_acls(self, login, args):
        """Make consul ACL rules from the given args or configuration file.

        {'rule': '', 'policy': 'deny'} is applied by default.

        Returns a list of dictionaries containing the rules and policies for this login.
        [{'rule':'/xivo/consul/path/', 'policy': 'write'}]
        Note: The ACL order is respected.
        """
        return []

    def get_acls(self, login, args):
        """returns a list of XiVO acls"""
        return []

    @abc.abstractmethod
    def get_ids(self, login, args):
        """Find the identifiers for a given login and arguments in the body request.

        Returns a tuple containing the unique identifier for this backend and
        the xivo user uuid for the the given login.
        """

    @abc.abstractmethod
    def verify_password(self, login, passwd):
        """Checks if a login/password combination is correct, returns True or False."""

    @staticmethod
    def should_be_loaded(config):
        """This method is called before to load the plugin. This method is not called
        if the plugin is not in enabled_plugins

        Return True if the plugin should be loaded and False otherwise.
        """
        return True
