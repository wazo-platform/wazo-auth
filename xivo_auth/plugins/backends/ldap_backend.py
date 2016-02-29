# -*- coding: utf-8 -*-

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

from __future__ import absolute_import

import ldap
import logging

logger = logging.getLogger(__name__)


class XivoLDAP(object):

    def __init__(self, config):
        self.config = config
        self.uri = self.config['uri']
        self.user_base_dn = self.config['user_base_dn']
        self.user_login_attribute = self.config['user_login_attribute']
        self.user_email_attribute = self.config.get('user_email_attribute', 'mail')
        self.ldapobj = None

        try:
            self.ldapobj = self._create_ldap_obj(self.uri)
        except ldap.LDAPError, exc:
            logger.exception('__init__: ldap.LDAPError (%r, %r, %r)', self.ldapobj, self.config, exc)
            self.ldapobj = None

    def _create_ldap_obj(self, uri):
        ldapobj = ldap.initialize(uri, 0)
        ldapobj.set_option(ldap.OPT_REFERRALS, 0)
        ldapobj.set_option(ldap.OPT_NETWORK_TIMEOUT, 2)
        ldapobj.set_option(ldap.OPT_TIMEOUT, 2)
        return ldapobj

    def perform_bind(self, username, password):
        if self.ldapobj is None:
            logger.warning('LDAP SERVER not responding')
            return False

        try:
            self.ldapobj.simple_bind_s(username, password)
            logger.debug('LDAP : simple bind done with %s on %s', username, self.uri)
        except ldap.INVALID_CREDENTIALS:
            logger.info('LDAP : simple bind failed with %s on %s : invalid credentials!', username, self.uri)
            return False
        except ldap.SERVER_DOWN:
            logger.warning('LDAP : SERVER not responding on %s', self.uri)
            return False

        return True

    def build_dn_with_config(self, login):
        return '{}={},{}'.format(self.user_login_attribute, login, self.user_base_dn)

    def perform_search_dn(self, username):
        filterstr = '{}={}'.format(self.user_login_attribute, username)
        dn, _ = self._perform_search(self.user_base_dn, ldap.SCOPE_SUBTREE,
                                     filterstr=filterstr,
                                     attrlist=[''])
        if not dn:
            logger.debug('LDAP : No user DN for user_base dn: %s and filterstr: %s', self.user_base_dn, filterstr)
        return dn

    def get_user_email(self, user_dn):
        _, obj = self._perform_search(user_dn, ldap.SCOPE_BASE,
                                      attrlist=[self.user_email_attribute])
        email = obj.get(self.user_email_attribute, None)
        email = email[0] if isinstance(email, list) else email
        if not email:
            logger.debug('LDAP : No email found for the user DN: %s', user_dn)
        return email

    def _perform_search(self, base, scope, filterstr='(objectClass=*)', attrlist=None):
        if self.ldapobj is None:
            logger.warning('LDAP SERVER not responding')
            return None, None

        try:
            results = self.ldapobj.search_ext_s(base, scope,
                                                filterstr=filterstr,
                                                attrlist=attrlist,
                                                sizelimit=1)
        except ldap.SERVER_DOWN:
            logger.warning('LDAP : SERVER not responding on %s', self.uri)
            return None, None
        except ldap.SIZELIMIT_EXCEEDED:
            logger.debug('LDAP : More than 1 result for base: %s and filterstr: %s', base, filterstr)
            return None, None

        if not results:
            logger.debug('LDAP : No result found for base: %s and filterstr: %s', base, filterstr)
            return None, None

        return results[0]
