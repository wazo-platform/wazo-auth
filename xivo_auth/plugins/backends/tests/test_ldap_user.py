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

from mock import patch, Mock, call
from hamcrest import assert_that, equal_to

from xivo_auth.plugins.backends.ldap_user import LDAPUser, DEFAULT_ACLS


@patch('xivo_auth.plugins.backends.ldap_user.XivoLDAP', Mock())
@patch('xivo_auth.plugins.backends.ldap_user.find_by')
class TestGetConsulACLS(unittest.TestCase):

    def setUp(self):
        config = {
            'ldap': {
                'uri': 'ldap://host:389',
                'user_base_dn': 'dc=example,dc=com',
                'user_login_attribute': 'uid'
            }
        }
        self.args = {'xivo_user_uuid': 'alice-uuid'}
        self.backend = LDAPUser(config)

    def test_that_get_consul_acls_calls_get_ids(self, find_by):
        expected_acls = [{'rule': 'xivo/private/alice-uuid', 'policy': 'write'}]
        result = self.backend.get_consul_acls('alice', self.args)
        assert_that(result, equal_to((expected_acls)))


@patch('xivo_auth.plugins.backends.ldap_user.XivoLDAP', Mock())
@patch('xivo_auth.plugins.backends.ldap_user.find_by')
class TestGetACLS(unittest.TestCase):

    def setUp(self):
        config = {
            'ldap': {
                'uri': 'ldap://host:389',
                'user_base_dn': 'dc=example,dc=com',
                'user_login_attribute': 'uid'
            }
        }
        self.args = {'xivo_user_uuid': 'alice-uuid'}
        self.backend = LDAPUser(config)

    def test_get_acls(self, find_by):
        result = self.backend.get_acls('alice', self.args)
        assert_that(result, equal_to((DEFAULT_ACLS)))


@patch('xivo_auth.plugins.backends.ldap_user.XivoLDAP', Mock())
@patch('xivo_auth.plugins.backends.ldap_user.find_by')
class TestGetIDS(unittest.TestCase):

    def setUp(self):
        config = {
            'ldap': {
                'uri': 'ldap://host:389',
                'user_base_dn': 'dc=example,dc=com',
                'user_login_attribute': 'uid'
            }
        }
        self.args = {'xivo_user_uuid': 'alice-uuid'}
        self.backend = LDAPUser(config)

    def test_that_get_ids_calls_the_dao(self, find_by):
        expected_result = ('alice-uuid', 'alice-uuid')
        result = self.backend.get_ids('alice', self.args)
        assert_that(result, equal_to(expected_result))

    def test_that_get_ids_raises_if_no_user(self, find_by):
        self.assertRaises(Exception, self.backend.get_ids, 'alice')


@patch('xivo_auth.plugins.backends.ldap_user.XivoLDAP', Mock())
@patch('xivo_auth.plugins.backends.ldap_user.find_by')
class TestVerifyPassword(unittest.TestCase):

    def setUp(self):
        self.config = {
            'ldap': {
                'uri': 'ldap://host:389',
                'user_base_dn': 'dc=example,dc=com',
                'user_login_attribute': 'uid'
            }
        }
        self.expected_user_dn = 'uid=foo,dc=example,dc=com'

    def test_that_verify_password_calls_perform_bind(self, find_by):
        backend = LDAPUser(self.config)
        backend.ldap.reset_mock()
        backend.ldap.perform_bind.return_value = True
        backend.ldap.get_user_email.return_value = 'foo@example.com'
        backend.ldap.build_dn_with_config.return_value = self.expected_user_dn
        find_by.return_value.uuid = 'alice-uuid'
        args = {}

        result = backend.verify_password('foo', 'bar', args)

        assert_that(result, equal_to(True))
        backend.ldap.perform_bind.assert_called_once_with(self.expected_user_dn, 'bar')

    def test_that_verify_password_calls_return_false_when_no_user_bind(self, find_by):
        backend = LDAPUser(self.config)
        backend.ldap.reset_mock()
        backend.ldap.perform_bind.return_value = False
        args = {}

        result = backend.verify_password('foo', 'bar', args)

        assert_that(result, equal_to(False))
        backend.ldap.perform_bind.assert_called_once_with(self.expected_user_dn, 'bar')

    def test_that_verify_password_calls_return_False_when_no_email_associated(self, find_by):
        backend = LDAPUser(self.config)
        backend.ldap.reset_mock()
        backend.ldap.perform_bind.return_value = True
        backend.ldap.get_user_email.return_value = 'foo@example.com'
        backend.ldap.build_dn_with_config.return_value = 'uid=foo,dc=example,dc=com'
        find_by.return_value.uuid = None
        args = {}

        result = backend.verify_password('foo', 'bar', args)

        assert_that(result, equal_to(False))
        assert_that(args, equal_to({}))

    def test_that_verify_password_calls_with_bind_anonymous(self, find_by):
        extended_config = {
            'ldap': {
                'bind_anonymous': True
            }
        }
        extended_config['ldap'].update(self.config['ldap'])
        backend = LDAPUser(extended_config)
        backend.ldap.reset_mock()
        backend.ldap.perform_bind.return_value = True
        backend.ldap.get_user_email.return_value = 'foo@example.com'
        backend.ldap.perform_search_dn.return_value = self.expected_user_dn
        find_by.return_value.uuid = 'alice-uuid'
        args = {}

        result = backend.verify_password('foo', 'bar', args)

        assert_that(result, equal_to(True))
        assert_that(args, equal_to({'xivo_user_uuid': 'alice-uuid'}))
        expected_call = [call('', ''), call(self.expected_user_dn, 'bar')]
        backend.ldap.perform_bind.assert_has_calls(expected_call)
        backend.ldap.perform_search_dn.assert_called_once_with('foo')

    def test_that_verify_password_calls_return_false_when_no_binding_with_anonymous(self, find_by):
        extended_config = {
            'ldap': {
                'bind_anonymous': True
            }
        }
        extended_config['ldap'].update(self.config['ldap'])
        backend = LDAPUser(extended_config)
        backend.ldap.reset_mock()
        backend.ldap.perform_bind.return_value = False
        args = {}

        result = backend.verify_password('foo', 'bar', args)

        assert_that(result, equal_to(False))
        backend.ldap.perform_bind.assert_called_once_with('', '')

    def test_that_verify_password_calls_with_bind_dn(self, find_by):
        extended_config = {
            'ldap': {
                'bind_dn': 'uid=foo,dc=example,dc=com',
                'bind_password': 'S3cr$t'
            }
        }
        extended_config['ldap'].update(self.config['ldap'])
        backend = LDAPUser(extended_config)
        backend.ldap.reset_mock()
        backend.ldap.perform_bind.return_value = True
        backend.ldap.get_user_email.return_value = 'foo@example.com'
        backend.ldap.perform_search_dn.return_value = self.expected_user_dn
        find_by.return_value.uuid = 'alice-uuid'
        args = {}

        result = backend.verify_password('foo', 'bar', args)

        assert_that(result, equal_to(True))
        assert_that(args, equal_to({'xivo_user_uuid': 'alice-uuid'}))
        expected_call = [call('uid=foo,dc=example,dc=com', 'S3cr$t'), call(self.expected_user_dn, 'bar')]
        backend.ldap.perform_bind.assert_has_calls(expected_call)
        backend.ldap.perform_search_dn.assert_called_once_with('foo')

    def test_that_verify_password_calls_with_missing_bind_password_try_bind(self, find_by):
        extended_config = {
            'ldap': {
                'bind_dn': 'uid=foo,dc=example,dc=com',
            }
        }
        extended_config['ldap'].update(self.config['ldap'])
        backend = LDAPUser(extended_config)
        backend.ldap.reset_mock()
        backend.ldap.perform_bind.return_value = True
        backend.ldap.get_user_email.return_value = 'foo@example.com'
        backend.ldap.perform_search_dn.return_value = self.expected_user_dn
        backend.ldap.build_dn_with_config.return_value = self.expected_user_dn
        find_by.return_value.uuid = 'alice-uuid'
        args = {}

        result = backend.verify_password('foo', 'bar', args)

        assert_that(result, equal_to(True))
        assert_that(args, equal_to({'xivo_user_uuid': 'alice-uuid'}))
        backend.ldap.build_dn_with_config.assert_called_once_with('foo')
        backend.ldap.perform_bind.assert_called_once_with(self.expected_user_dn, 'bar')


class TestShouldBeLoaded(unittest.TestCase):

    def test_that_should_be_loaded_return_false_when_no_config(self):
        config = {}
        result = LDAPUser.should_be_loaded(config)
        assert_that(result, equal_to(False))

    def test_that_should_be_loaded_return_true(self):
        config = {'ldap': {}}
        result = LDAPUser.should_be_loaded(config)
        assert_that(result, equal_to(False))
