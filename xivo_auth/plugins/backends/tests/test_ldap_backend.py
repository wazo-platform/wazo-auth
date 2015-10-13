# -*- coding: utf-8 -*-

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

import unittest
import ldap
from mock import Mock, patch
from xivo_auth.plugins.backends.ldap_backend import XivoLDAP


class TestXivoLDAP(unittest.TestCase):

    @patch('ldap.initialize')
    def test_xivo_ldap_init(self, ldap_initialize):
        ldapobj = ldap_initialize.return_value = Mock()

        config = {
            'uri': 'ldap://host:389',
            'bind_dn_format': 'uid={username},dc=example,dc=com',
            'domain': 'example.com',
        }

        XivoLDAP(config)

        ldap_initialize.assert_called_once_with(config['uri'], 0)
        ldapobj.set_option.assert_any_call(ldap.OPT_REFERRALS, 0)
        ldapobj.set_option.assert_any_call(ldap.OPT_NETWORK_TIMEOUT, 2)
        ldapobj.set_option.assert_any_call(ldap.OPT_TIMEOUT, 2)

    @patch('ldap.initialize', Mock())
    def test_that_perform_bind(self):
        config = {
            'uri': 'ldap://host:389',
            'bind_dn_format': 'uid={username},dc=example,dc=com',
            'domain': 'example.com',
        }

        xivo_ldap = XivoLDAP(config)
        result = xivo_ldap.perform_bind('username', 'password')
        self.assertEquals(result, True)

    @patch('ldap.initialize')
    def test_that_perform_bind_return_false_when_no_ldap(self, ldap_initialize):
        ldap_initialize.side_effect = ldap.LDAPError()
        config = {
            'uri': 'wrong://uri:1234',
        }

        xivo_ldap = XivoLDAP(config)
        result = xivo_ldap.perform_bind('username', 'password')
        self.assertEquals(result, False)

    @patch('ldap.initialize')
    def test_that_perform_bind_return_false_when_no_wrong_credential(self, ldap_initialize):
        ldapobj = ldap_initialize.return_value = Mock()

        config = {
            'uri': 'ldap://host:389',
            'bind_dn_format': 'uid={username},dc=example,dc=com',
            'domain': 'example.com',
        }

        xivo_ldap = XivoLDAP(config)
        ldapobj.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS()
        result = xivo_ldap.perform_bind('username', 'password')
        self.assertEquals(result, False)
