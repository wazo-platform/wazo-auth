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

import unittest
import ldap
from mock import Mock, patch
from xivo_auth.plugins.backends.ldap_backend import XivoLDAP


class TestXivoLDAP(unittest.TestCase):

    def setUp(self):
        self.config = {
            'uri': 'ldap://host:389',
            'user_base_dn': 'dc=example,dc=com',
            'user_login_attribute': 'uid'
        }

    @patch('ldap.initialize')
    def test_xivo_ldap_init(self, ldap_initialize):
        ldapobj = ldap_initialize.return_value = Mock()

        XivoLDAP(self.config)

        ldap_initialize.assert_called_once_with(self.config['uri'], 0)
        ldapobj.set_option.assert_any_call(ldap.OPT_REFERRALS, 0)
        ldapobj.set_option.assert_any_call(ldap.OPT_NETWORK_TIMEOUT, 2)
        ldapobj.set_option.assert_any_call(ldap.OPT_TIMEOUT, 2)

    @patch('ldap.initialize', Mock())
    def test_that_perform_bind(self):
        xivo_ldap = XivoLDAP(self.config)

        result = xivo_ldap.perform_bind('username', 'password')
        self.assertEquals(result, True)

    @patch('ldap.initialize')
    def test_that_perform_bind_return_false_when_no_ldap(self, ldap_initialize):
        ldap_initialize.side_effect = ldap.LDAPError()
        xivo_ldap = XivoLDAP(self.config)

        result = xivo_ldap.perform_bind('username', 'password')
        self.assertEquals(result, False)

    @patch('ldap.initialize')
    def test_that_perform_bind_return_false_when_no_wrong_credential(self, ldap_initialize):
        ldapobj = ldap_initialize.return_value = Mock()

        xivo_ldap = XivoLDAP(self.config)
        ldapobj.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS()
        result = xivo_ldap.perform_bind('username', 'password')
        self.assertEquals(result, False)

    @patch('ldap.initialize')
    def test_get_user_email(self, ldap_initialize):
        ldapobj = ldap_initialize.return_value = Mock()
        xivo_ldap = XivoLDAP(self.config)
        ldapobj.search_ext_s.return_value = [('dn', {'mail': 'value'})]

        result = xivo_ldap.get_user_email('user_dn')
        self.assertEquals(result, 'value')

    @patch('ldap.initialize')
    def test_that_perform_search_dn(self, ldap_initialize):
        ldapobj = ldap_initialize.return_value = Mock()
        xivo_ldap = XivoLDAP(self.config)
        ldapobj.search_ext_s.return_value = [('dn', {'attr': 'value'})]

        result = xivo_ldap.perform_search_dn('username')
        self.assertEquals(result, 'dn')

    @patch('ldap.initialize')
    def test_that_perform_search_return_none_when_server_down(self, ldap_initialize):
        ldapobj = ldap_initialize.return_value = Mock()
        xivo_ldap = XivoLDAP(self.config)
        ldapobj.search_ext_s.side_effect = ldap.SERVER_DOWN()

        result = xivo_ldap.perform_search_dn('username')
        self.assertEquals(result, None)

    @patch('ldap.initialize')
    def test_that_perform_search_return_none_when_no_result(self, ldap_initialize):
        ldapobj = ldap_initialize.return_value = Mock()
        xivo_ldap = XivoLDAP(self.config)
        ldapobj.search_ext_s.return_value = []

        result = xivo_ldap.perform_search_dn('username')
        self.assertEquals(result, None)
