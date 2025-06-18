# Copyright 2015-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import abc
import logging
import os
from collections import namedtuple
from collections.abc import Mapping
from typing import TYPE_CHECKING, Protocol, TypedDict

if TYPE_CHECKING:
    from stevedore.extension import Extension


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

        these data are used in the body of the GET and POST of the /token
        """
        metadata = {
            'auth_id': None,
            'username': login,
            'xivo_uuid': self.get_xivo_uuid(args),
            'pbx_user_uuid': None,
        }

        return metadata

    def get_persistent_metadata(self, login, args):
        """return metadata to persist across sessions
        through the refresh token
        """
        metadata = {}

        return metadata

    @abc.abstractmethod
    def verify_password(self, login, passwd, args):
        """Checks if a login/password combination is correct, returns True or False.

        It's possible to pass values through the args parameter. These values
        will be passed to the other methods of the plugin.
        """


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
        user_uuid = self._user_service.get_user_uuid_by_login(login)
        user = self._user_service.list_users(uuid=user_uuid)[0]
        metadata = {
            'uuid': user['uuid'],
            'tenant_uuid': user['tenant_uuid'],
            'auth_id': user['uuid'],
            'pbx_user_uuid': None,
            'xivo_uuid': self.get_xivo_uuid(args),
        }
        return metadata

    def get_persistent_metadata(self, login, args):
        """return metadata to persist across sessions
        through the refresh token
        """
        metadata = {}

        return metadata

    def get_xivo_uuid(self, _args):
        """returns the xivo-uuid for this given backend

        Will return the XIVO_UUID environment variable if the backend does not implement
        this method.
        """
        return DEFAULT_XIVO_UUID


EmailDestination = namedtuple('EmailDestination', ['name', 'address'])


class BaseEmailNotification(metaclass=abc.ABCMeta):
    def __init__(self, *args, **kwargs):
        """Initialize this plugin instance from the given configuration"""
        pass

    def send_confirmation(self, context: dict) -> None:
        """Send confirmation email link"""
        pass

    def send_password_reset(self, context: dict) -> None:
        """Send password reset email link"""
        pass


class IDPPluginDependencies(TypedDict, total=False):
    backends: Mapping[str, Extension]
    ...


class IDPPlugin(Protocol):
    loaded: bool = False
    """
    Indicates that the plugin has been fully loaded successfully
    (load method executed completely without errors)
    """

    authentication_method: str
    """
    identifier for this auth method
    """

    def load(self, dependencies: IDPPluginDependencies):
        ...

    def can_authenticate(self, args: dict) -> bool:
        """
        Evaluate if this plugin is applicable to a login request based on login request args

        Returns true if the plugin can authenticate the login request
        based on the login request information, false otherwise.
        """
        ...

    def verify_auth(self, args: dict) -> tuple[BaseAuthenticationBackend, str]:
        """
        Verify(authenticate) login request and return an authentication backend and a login string
        """
        ...

    def get_backend(self, args: dict) -> BaseAuthenticationBackend:
        """
        Return an authentication backend appropriate for the given authentication request
        """
        ...
