# Copyright 2015-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import abc
import os
import logging

DEFAULT_XIVO_UUID = os.getenv('XIVO_UUID')
logger = logging.getLogger(__name__)


class BaseAuthenticationBackend(metaclass=abc.ABCMeta):
    def __init__(self):
        """Initialize this backend instance from the given configuration"""
        pass

    def load(self, dependencies):
        pass

    def get_acl(self, login, args):
        """returns an acl"""
        return []

    def get_xivo_uuid(self, _args):
        """returns the xivo-uuid for this given backend

        Will return the XIVO_UUID environment variable if the backend does not implement
        this method.
        """
        return DEFAULT_XIVO_UUID

    def get_metadata(self, login, args):
        """return user related data

        these data are used in the body of the GET and POST of the /token and
        also used for ACL rendering
        """
        metadata = {
            'auth_id': None,
            'username': login,
            'xivo_uuid': self.get_xivo_uuid(args),
            'pbx_user_uuid': None,
        }

        return metadata

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
        if the plugin is not in enabled_backend_plugins.

        Return True if the plugin should be loaded and False otherwise.
        """
        return True


class BaseMetadata(metaclass=abc.ABCMeta):
    def __init__(self):
        """Initialize this plugin instance from the given configuration"""
        pass

    def load(self, dependencies):
        self._user_service = dependencies['user_service']

    def get_token_metadata(self, login, args):
        """return user related data

        These data are used in the body of the GET and POST of the /token
        """
        user = self._user_service.list_users(username=login)[0]
        metadata = {
            'uuid': user['uuid'],
            'tenant_uuid': user['tenant_uuid'],
            'auth_id': user['uuid'],
            'pbx_user_uuid': None,
            'xivo_uuid': self.get_xivo_uuid(args),
        }
        return metadata

    def get_xivo_uuid(self, _args):
        """returns the xivo-uuid for this given backend

        Will return the XIVO_UUID environment variable if the backend does not implement
        this method.
        """
        return DEFAULT_XIVO_UUID
