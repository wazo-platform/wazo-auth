# -*- coding: utf-8 -*-
#
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
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
import logging

from xivo_confd_client import Client
from wazo_auth.helpers import LazyTemplateRenderer

DEFAULT_XIVO_UUID = os.getenv('XIVO_UUID')
logger = logging.getLogger(__name__)


class BaseAuthenticationBackend(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self):
        """Initialize this backend instance from the given configuration"""
        pass

    def load(self, dependencies):
        pass

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


class ACLRenderingBackend(object):

    def render_acl(self, acl_templates, get_data_fn, *args, **kwargs):
        renderer = LazyTemplateRenderer(acl_templates, get_data_fn, *args, **kwargs)
        return renderer.render()


class UserAuthenticationBackend(BaseAuthenticationBackend, ACLRenderingBackend):

    __metaclass__ = abc.ABCMeta

    def load(self, dependencies):
        super(UserAuthenticationBackend, self).load(dependencies)
        self._config = dependencies['config']
        self._confd_config = self._config['confd']

    @abc.abstractmethod
    def get_ids(self, login, args):
        super(UserAuthenticationBackend, self).get_ids(login, args)

    @abc.abstractmethod
    def verify_password(self, login, passwd, args):
        super(UserAuthenticationBackend, self).verify_password(login, passwd, args)

    def get_user_data(self, **kwargs):
        local_token_manager = self._config.get('local_token_manager')
        if not local_token_manager:
            logger.info('no local token manager')
            return {}

        token = local_token_manager.get_token()
        confd_client = Client(token=token, **self._confd_config)
        response = confd_client.users.list(**kwargs)
        for user in response['items']:
            voicemail = user.get('voicemail')
            voicemails = [voicemail['id']] if voicemail else []
            lines, sip, sccp, custom, extensions = [], [], [], [], []
            for line in user['lines']:
                lines.append(line['id'])
                endpoint_custom = line.get('endpoint_custom')
                endpoint_sip = line.get('endpoint_sip')
                endpoint_sccp = line.get('endpoint_sccp')
                if endpoint_custom:
                    custom.append(endpoint_custom['id'])
                elif endpoint_sip:
                    sip.append(endpoint_sip['id'])
                elif endpoint_sccp:
                    sccp.append(endpoint_sccp['id'])
                for extension in line['extensions']:
                    extensions.append(extension['id'])
            return {
                'id': user['id'],
                'uuid': user['uuid'],
                'voicemails': voicemails,
                'lines': lines,
                'extensions': extensions,
                'endpoint_sip': sip,
                'endpoint_sccp': sccp,
                'endpoint_custom': custom,
                'agent': user['agent'],
            }
        return {}
