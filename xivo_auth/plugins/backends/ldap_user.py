# -*- coding: utf-8 -*-
#
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

import xivo_dao

from ldap_backend import XivoLDAP
from xivo_auth import BaseAuthenticationBackend
from xivo_dao import user_dao


class LDAPUser(BaseAuthenticationBackend):

    def __init__(self, config):
        self.config = config['ldap']
        self.domain = self.config['domain']
        self.ldap = XivoLDAP(self.config)
        xivo_dao.init_db_from_config(config)

    def get_consul_acls(self, username, args):
        identifier, _ = self.get_ids(username, args)
        rules = [{'rule': 'xivo/private/{identifier}'.format(identifier=identifier),
                  'policy': 'write'}]
        return rules

    def get_acls(self, login, args):
        return ['acl:dird']

    def get_ids(self, username, args):
        user_uuid = user_dao.get_uuid_by_email(self._set_username_with_domain(username))
        return user_uuid, user_uuid

    def verify_password(self, username, password):
        return self.ldap.perform_bind(self._set_username_dn(username), password)

    def _get_username(self, username):
        if '@' in username:
            username, _ = username.split('@', 1)
        return username

    def _set_username_dn(self, username):
        return '{prefix}={username},{basedn}'.format(prefix=self.config['prefix'],
                                                     username=self._get_username(username),
                                                     basedn=self.config['basedn'])

    def _set_username_with_domain(self, username):
        if '@' not in username:
            username = '{username}@{domain}'.format(username=username, domain=self.domain)
        return username
