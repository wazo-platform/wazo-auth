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

import unittest

from mock import patch, Mock
from hamcrest import assert_that, equal_to

from xivo_auth.plugins.backends.ldap_user import LDAPUser


@patch('xivo_auth.plugins.backends.ldap_user.XivoLDAP', Mock())
@patch('xivo_auth.plugins.backends.ldap_user.find_by')
class TestGetConsulACLS(unittest.TestCase):

    def setUp(self):
        config = {
            'ldap': {
                'uri': 'ldap://host:389',
                'bind_dn_format': 'uid={username},dc=example,dc=com',
                'domain': 'example.com',
            }
        }
        self.args = None
        self.backend = LDAPUser(config)

    def test_that_get_consul_acls_calls_get_ids(self, find_by):
        find_by.return_value.uuid = 'alice-uuid'

        result = self.backend.get_consul_acls('alice', self.args)

        acls = [{'rule': 'xivo/private/alice-uuid', 'policy': 'write'}]
        assert_that(result, equal_to((acls)))
        find_by.assert_called_once_with(email='alice@example.com')


@patch('xivo_auth.plugins.backends.ldap_user.XivoLDAP', Mock())
@patch('xivo_auth.plugins.backends.ldap_user.find_by')
class TestGetACLS(unittest.TestCase):

    def setUp(self):
        config = {
            'ldap': {
                'uri': 'ldap://host:389',
                'bind_dn_format': 'uid={username},dc=example,dc=com',
                'domain': 'example.com',
            }
        }
        self.args = None
        self.backend = LDAPUser(config)

    def test_that_get_consul_acls_calls_get_ids(self, find_by):
        result = self.backend.get_acls('alice', self.args)

        acls = ['dird']
        assert_that(result, equal_to((acls)))


@patch('xivo_auth.plugins.backends.ldap_user.XivoLDAP', Mock())
@patch('xivo_auth.plugins.backends.ldap_user.find_by')
class TestGetIDS(unittest.TestCase):

    def setUp(self):
        config = {
            'ldap': {
                'uri': 'ldap://host:389',
                'bind_dn_format': 'uid={username},dc=example,dc=com',
                'domain': 'example.com',
            }
        }
        self.args = None
        self.backend = LDAPUser(config)

    def test_that_get_ids_calls_the_dao(self, find_by):
        find_by.return_value.uuid = 'alice-uuid'
        expected_result = ('alice-uuid', 'alice-uuid')

        result = self.backend.get_ids('alice', self.args)

        assert_that(result, equal_to(expected_result))
        find_by.assert_called_once_with(email='alice@example.com')

    def test_that_get_ids_raises_if_no_user(self, find_by):
        find_by.return_value.uuid = None
        self.assertRaises(Exception, self.backend.get_ids, 'alice')


@patch('xivo_auth.plugins.backends.ldap_user.XivoLDAP', Mock())
@patch('xivo_auth.plugins.backends.ldap_user.find_by')
class TestVerifyPassword(unittest.TestCase):

    def test_that_verify_password_calls_perform_bind(self, find_by):
        config = {
            'ldap': {
                'uri': 'ldap://host:389',
                'bind_dn_format': 'uid={username},dc=example,dc=com',
                'domain': 'example.com',
            }
        }
        backend = LDAPUser(config)
        backend.ldap.perform_bind.return_value = True
        find_by.return_value.uuid = 'alice-uuid'

        result = backend.verify_password('foo', 'bar')

        assert_that(result, equal_to(True))
        backend.ldap.perform_bind.assert_called_once_with('uid=foo,dc=example,dc=com', 'bar')

    def test_that_verify_password_calls_return_False_when_no_email_associated(self, find_by):
        config = {
            'ldap': {
                'uri': 'ldap://host:389',
                'bind_dn_format': 'uid={username},dc=example,dc=com',
                'domain': 'example.com',
            }
        }
        backend = LDAPUser(config)
        backend.ldap.perform_bind.return_value = True
        find_by.return_value.uuid = None

        result = backend.verify_password('foo', 'bar')

        assert_that(result, equal_to(False))
