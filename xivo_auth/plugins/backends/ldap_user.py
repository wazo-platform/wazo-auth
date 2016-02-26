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

DEFAULT_ACLS = ['confd.users.me.read',
                'confd.users.me.update',
                'confd.users.me.funckeys.*.*',
                'confd.users.me.#.read',
                'ctid-ng.calls.create',
                'ctid-ng.calls.*.read',
                'ctid-ng.calls.*.delete',
                'dird.#.me.read',
                'dird.directories.favorites.#',
                'dird.directories.lookup.*.headers.read',
                'dird.directories.lookup.*.read',
                'dird.directories.personal.*.read',
                'dird.personal.#']


class LDAPUser(BaseAuthenticationBackend):

    def __init__(self, config):
        self.config = config['ldap']
        self.bind_dn = self.config.get('bind_dn', '')
        self.bind_password = self.config.get('bind_password', '')
        self.bind_anonymous = self.config.get('bind_anonymous', False)

        self.ldap = XivoLDAP(self.config)

    def get_consul_acls(self, username, args):
        identifier, _ = self.get_ids(username, args)
        rules = [{'rule': 'xivo/private/{identifier}'.format(identifier=identifier),
                  'policy': 'write'}]
        return rules

    def get_acls(self, login, args):
        return DEFAULT_ACLS

    def get_ids(self, username, args):
        user_uuid = args['xivo_user_uuid']
        return user_uuid, user_uuid

    def verify_password(self, username, password, args):
        if self.bind_anonymous or (self.bind_dn and self.bind_password):
            if self.ldap.perform_bind(self.bind_dn, self.bind_password):
                user_dn = self.ldap.perform_search_dn(username)
            else:
                return False
        else:
            user_dn = self.ldap.build_dn_with_config(username)

        if not user_dn or not self.ldap.perform_bind(user_dn, password):
            return False

        user_email = self.ldap.get_user_email(user_dn)
        if not user_email:
            return False

        xivo_user_uuid = self._get_xivo_user_uuid_by_ldap_attribute(user_email)
        if not xivo_user_uuid:
            return False

        args['xivo_user_uuid'] = xivo_user_uuid

        return True

    @staticmethod
    def should_be_loaded(config):
        return bool(config.get('ldap', False))

    def _get_xivo_user_uuid_by_ldap_attribute(self, user_email):
        with session_scope():
            xivo_user = find_by(email=user_email)
            if not xivo_user:
                logger.warning('%s does not have an email associated with a XiVO user', user_email)
                return xivo_user
            return xivo_user.uuid
