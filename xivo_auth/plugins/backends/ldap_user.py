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

import logging

from ldap_backend import XivoLDAP
from xivo_auth import BaseAuthenticationBackend

from xivo_dao.resources.user.dao import find_by
from xivo_dao.helpers.db_utils import session_scope

logger = logging.getLogger(__name__)


class LDAPUser(BaseAuthenticationBackend):

    def __init__(self, config):
        self.config = config['ldap']
        self.bind_dn_format = self.config['bind_dn_format']
        self.ldap = XivoLDAP(self.config)

    def get_consul_acls(self, username, args):
        identifier, _ = self.get_ids(username, args)
        rules = [{'rule': 'xivo/private/{identifier}'.format(identifier=identifier),
                  'policy': 'write'}]
        return rules

    def get_acls(self, login, args):
        return ['dird.#.me',
                'confd.users.me.read',
                'confd.users.me.update',
                'confd.users.me.funckeys.*.*',
                'confd.users.me.#.read']

    def get_ids(self, username, args):
        user_uuid = self._get_xivo_user_uuid_by_ldap_username(username)
        return user_uuid, user_uuid

    def verify_password(self, username, password):
        if not self.ldap.perform_bind(self._set_username_dn(username), password):
            return False
        if self._get_xivo_user_uuid_by_ldap_username(username) is None:
            return False
        return True

    def _get_xivo_user_uuid_by_ldap_username(self, username):
        email = self._set_username_with_domain(username)
        with session_scope():
            xivo_user = find_by(email=email)
            if not xivo_user:
                logger.warning('%s does not have an email associated with a XiVO user', username)
                return xivo_user
            return xivo_user.uuid

    def _get_username(self, username):
        if '@' in username:
            username, _ = username.split('@', 1)
        return username

    def _set_username_dn(self, username):
        return self.bind_dn_format.format(username=self._get_username(username))

    def _set_username_with_domain(self, username):
        if '@' not in username:
            username = '{username}@{domain}'.format(username=username, domain=self.config['domain'])
        return username
