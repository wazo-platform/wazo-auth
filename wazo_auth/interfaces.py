# -*- coding: utf-8 -*-
# Copyright 2015-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

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
        """returns a list of acls"""
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
        metadata = dict(xivo_uuid=self.get_xivo_uuid(args))

        # Old plugin had a get_ids method that returned the auth_id and the xivo_user_uuid
        if hasattr(self, 'get_ids'):
            auth_id, xivo_user_uuid = self.get_ids(login, args)
            metadata['auth_id'] = auth_id
            metadata['xivo_user_uuid'] = xivo_user_uuid

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
