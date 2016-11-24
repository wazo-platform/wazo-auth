# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Avencall
# Copyright (C) 2016 Proformatique, Inc.
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
import os

DEFAULT_XIVO_UUID = os.getenv('XIVO_UUID')


class BaseAuthenticationBackend(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self, config):
        """Initialize this backend instance from the given configuration"""

    def get_acls(self, login, args):
        """returns a list of XiVO acls"""
        return []

    def get_xivo_uuid(self, _args):
        """returns the xivo-uuid for this given backend

        Will return the XIVO_UUID environment variable if the backend does not implement
        this method.
        """
        return DEFAULT_XIVO_UUID

    @abc.abstractmethod
    def get_ids(self, login, args):
        """Find the identifiers for a given login and arguments in the body request.

        Returns a tuple containing the unique identifier for this backend and
        the xivo user uuid for the the given login.
        """

    @abc.abstractmethod
    def verify_password(self, login, passwd, args):
        """Checks if a login/password combination is correct, returns True or False.

        It's possible to pass values through the args parameter. These values
        will be passed to the other methods of the plugin.
        """

    @staticmethod
    def should_be_loaded(config):
        """Checks if a plugin should be loaded

        This method is called before plugins are loaded. This method is not called
        if the plugin is not in enabled_plugins.

        Return True if the plugin should be loaded and False otherwise.
        """
        return True
