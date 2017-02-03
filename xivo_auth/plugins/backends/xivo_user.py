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

import logging

from jinja2 import StrictUndefined, Template
from jinja2.exceptions import UndefinedError
from xivo_confd_client import Client
from xivo_auth import BaseAuthenticationBackend
from xivo_dao.resources.user import dao as user_dao
from xivo_dao.helpers.db_utils import session_scope

logger = logging.getLogger(__name__)


class XiVOUser(BaseAuthenticationBackend):

    def __init__(self, config):
        super(XiVOUser, self).__init__(config)
        self._config = config
        self._confd_config = config['confd']

    def get_acls(self, login, args):
        # TODO don't botter calling xivo-confd if there no acl_templates
        # TODO check if there's a way to check if a substitution is required?
        logger.debug('get_acls(%s, %s)', login, args)
        user_data = self._get_user_data(username=login)
        logger.debug('%s', user_data)
        return self._render_acl(args.get('acl_templates'), user_data)

    def get_ids(self, username, args):
        with session_scope():
            user = user_dao.get_by(username=username, enableclient=1)
            return user.uuid, user.uuid

    def verify_password(self, login, password, args):
        with session_scope():
            user = user_dao.find_by(username=login, password=password, enableclient=1)
            return user is not None

    def _get_user_data(self, **kwargs):
        confd_client = Client(token=self._config.get('token'), **self._confd_config)
        response = confd_client.users.list(**kwargs)
        for user in response['items']:
            voicemail_id = user.get('voicemail', {}).get('id')
            voicemails = [voicemail_id] if voicemail_id else []
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
            }
        return {}

    def _render_acl(self, acl_templates, user_data):
        acls = []
        for acl_template in acl_templates:
            template = Template(acl_template, undefined=StrictUndefined)
            try:
                acl = template.render(user_data)
            except UndefinedError:
                continue
            acls.append(acl)
        return acls
