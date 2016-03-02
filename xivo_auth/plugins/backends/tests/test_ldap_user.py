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

import ldap
import unittest

from mock import patch, Mock, call
from hamcrest import assert_that, equal_to

from xivo_auth.plugins.backends.ldap_user import LDAPUser, _XivoLDAP, DEFAULT_ACLS


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


@patch('xivo_auth.plugins.backends.ldap_user._XivoLDAP')
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
        self.expected_user_email = 'foo@example.com'
        obj = Mock()
        obj.return_value.mail.return_value = self.expected_user_email
        self.search_obj_result = (self.expected_user_dn, obj)

    def test_that_verify_password_return_false_when_ldaperror(self, find_by, xivo_ldap):
        backend = LDAPUser(self.config)
        xivo_ldap.side_effect = ldap.LDAPError
        args = {}

        result = backend.verify_password('foo', 'bar', args)
        assert_that(result, equal_to(False))

    def test_that_verify_password_return_false_when_serverdown(self, find_by, xivo_ldap):
        backend = LDAPUser(self.config)
        xivo_ldap.side_effect = ldap.SERVER_DOWN
        args = {}

        result = backend.verify_password('foo', 'bar', args)
        assert_that(result, equal_to(False))

    def test_that_verify_password_calls_perform_bind(self, find_by, xivo_ldap):
        backend = LDAPUser(self.config)

        xivo_ldap = xivo_ldap.return_value
        xivo_ldap.perform_bind.return_value = True
        xivo_ldap.perform_search.return_value = self.search_obj_result
        find_by.return_value.uuid = 'alice-uuid'
        args = {}

        result = backend.verify_password('foo', 'bar', args)

        assert_that(result, equal_to(True))
        xivo_ldap.perform_bind.assert_called_once_with(self.expected_user_dn, 'bar')

    def test_that_verify_password_escape_dn_chars(self, find_by, xivo_ldap):
        backend = LDAPUser(self.config)

        xivo_ldap = xivo_ldap.return_value
        xivo_ldap.perform_bind.return_value = True
        xivo_ldap.perform_search.return_value = ('uid=fo\+o,dc=example,dc=com', Mock())
        find_by.return_value.uuid = 'alice-uuid'
        args = {}

        result = backend.verify_password('fo+o', 'bar', args)

        assert_that(result, equal_to(True))
        xivo_ldap.perform_bind.assert_called_once_with('uid=fo\+o,dc=example,dc=com', 'bar')

    def test_that_verify_password_escape_filter_chars(self, find_by, xivo_ldap):
        extended_config = {
            'ldap': {
                'bind_anonymous': True
            }
        }
        extended_config['ldap'].update(self.config['ldap'])
        backend = LDAPUser(self.config)

        xivo_ldap = xivo_ldap.return_value
        xivo_ldap.perform_bind.return_value = True
        xivo_ldap.perform_search.return_value = ('uid=fo\+o,dc=example,dc=com', Mock())
        find_by.return_value.uuid = 'alice-uuid'
        args = {}

        result = backend.verify_password('fo+o', 'bar', args)

        assert_that(result, equal_to(True))
        xivo_ldap.perform_search.assert_called_once_with('uid=fo\+o,dc=example,dc=com', 0, attrlist=['mail'])

    def test_that_verify_password_calls_return_false_when_no_user_bind(self, find_by, xivo_ldap):
        backend = LDAPUser(self.config)
        xivo_ldap = xivo_ldap.return_value
        xivo_ldap.perform_bind.return_value = False
        args = {}

        result = backend.verify_password('foo', 'bar', args)

        assert_that(result, equal_to(False))
        xivo_ldap.perform_bind.assert_called_once_with(self.expected_user_dn, 'bar')

    def test_that_verify_password_calls_return_False_when_no_email_associated(self, find_by, xivo_ldap):
        backend = LDAPUser(self.config)
        xivo_ldap = xivo_ldap.return_value
        xivo_ldap.perform_bind.return_value = True
        xivo_ldap.perform_search.return_value = self.search_obj_result
        find_by.return_value.uuid = None
        args = {}

        result = backend.verify_password('foo', 'bar', args)

        assert_that(result, equal_to(False))
        assert_that(args, equal_to({}))

    def test_that_verify_password_calls_with_bind_anonymous(self, find_by, xivo_ldap):
        extended_config = {
            'ldap': {
                'bind_anonymous': True
            }
        }
        extended_config['ldap'].update(self.config['ldap'])
        backend = LDAPUser(extended_config)
        xivo_ldap = xivo_ldap.return_value
        xivo_ldap.perform_bind.return_value = True
        xivo_ldap.perform_search.return_value = self.search_obj_result
        find_by.return_value.uuid = 'alice-uuid'
        args = {}

        result = backend.verify_password('foo', 'bar', args)

        assert_that(result, equal_to(True))
        assert_that(args, equal_to({'xivo_user_uuid': 'alice-uuid'}))
        expected_call = [call('', ''), call(self.expected_user_dn, 'bar')]
        xivo_ldap.perform_bind.assert_has_calls(expected_call)

    def test_that_verify_password_calls_return_false_when_no_binding_with_anonymous(self, find_by, xivo_ldap):
        extended_config = {
            'ldap': {
                'bind_anonymous': True
            }
        }
        extended_config['ldap'].update(self.config['ldap'])
        xivo_ldap = xivo_ldap.return_value
        backend = LDAPUser(extended_config)
        xivo_ldap.perform_bind.return_value = False
        args = {}

        result = backend.verify_password('foo', 'bar', args)

        assert_that(result, equal_to(False))
        xivo_ldap.perform_bind.assert_called_once_with('', '')

    def test_that_verify_password_calls_with_bind_dn(self, find_by, xivo_ldap):
        extended_config = {
            'ldap': {
                'bind_dn': 'uid=foo,dc=example,dc=com',
                'bind_password': 'S3cr$t'
            }
        }
        extended_config['ldap'].update(self.config['ldap'])
        backend = LDAPUser(extended_config)
        xivo_ldap = xivo_ldap.return_value
        xivo_ldap.perform_bind.return_value = True
        xivo_ldap.perform_search.return_value = self.search_obj_result
        find_by.return_value.uuid = 'alice-uuid'
        args = {}

        result = backend.verify_password('foo', 'bar', args)

        assert_that(result, equal_to(True))
        assert_that(args, equal_to({'xivo_user_uuid': 'alice-uuid'}))
        expected_call = [call('uid=foo,dc=example,dc=com', 'S3cr$t'), call(self.expected_user_dn, 'bar')]
        xivo_ldap.perform_bind.assert_has_calls(expected_call)

    def test_that_verify_password_calls_with_missing_bind_password_try_bind(self, find_by, xivo_ldap):
        extended_config = {
            'ldap': {
                'bind_dn': 'uid=foo,dc=example,dc=com',
            }
        }
        extended_config['ldap'].update(self.config['ldap'])
        backend = LDAPUser(extended_config)
        xivo_ldap = xivo_ldap.return_value
        xivo_ldap.perform_bind.return_value = True
        xivo_ldap.perform_search.return_value = self.search_obj_result
        find_by.return_value.uuid = 'alice-uuid'
        args = {}

        result = backend.verify_password('foo', 'bar', args)

        assert_that(result, equal_to(True))
        assert_that(args, equal_to({'xivo_user_uuid': 'alice-uuid'}))
        xivo_ldap.perform_bind.assert_called_once_with(self.expected_user_dn, 'bar')


class TestShouldBeLoaded(unittest.TestCase):

    def test_that_should_be_loaded_return_false_when_no_config(self):
        config = {}
        result = LDAPUser.should_be_loaded(config)
        assert_that(result, equal_to(False))

    def test_that_should_be_loaded_return_true(self):
        config = {'ldap': {}}
        result = LDAPUser.should_be_loaded(config)
        assert_that(result, equal_to(False))


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

        _XivoLDAP(self.config)

        ldap_initialize.assert_called_once_with(self.config['uri'], 0)
        ldapobj.set_option.assert_any_call(ldap.OPT_REFERRALS, 0)
        ldapobj.set_option.assert_any_call(ldap.OPT_NETWORK_TIMEOUT, 2)
        ldapobj.set_option.assert_any_call(ldap.OPT_TIMEOUT, 2)

    @patch('ldap.initialize', Mock())
    def test_that_perform_bind(self):
        xivo_ldap = _XivoLDAP(self.config)

        result = xivo_ldap.perform_bind('username', 'password')
        self.assertEquals(result, True)

    @patch('ldap.initialize')
    def test_that_perform_bind_return_false_when_no_wrong_credential(self, ldap_initialize):
        ldapobj = ldap_initialize.return_value = Mock()

        xivo_ldap = _XivoLDAP(self.config)
        ldapobj.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS()
        result = xivo_ldap.perform_bind('username', 'password')
        self.assertEquals(result, False)

    @patch('ldap.initialize')
    def test_that_perform_search(self, ldap_initialize):
        ldapobj = ldap_initialize.return_value = Mock()
        xivo_ldap = _XivoLDAP(self.config)
        ldapobj.search_ext_s.return_value = ['result1']

        result = xivo_ldap.perform_search('base', 'scope')
        self.assertEquals(result, 'result1')

    @patch('ldap.initialize')
    def test_that_perform_search_return_none_when_multiple_result(self, ldap_initialize):
        ldapobj = ldap_initialize.return_value = Mock()
        xivo_ldap = _XivoLDAP(self.config)
        ldapobj.search_ext_s.side_effect = ldap.SIZELIMIT_EXCEEDED()

        result_dn, result_attr = xivo_ldap.perform_search('base', 'scope')
        self.assertEquals(result_dn, None)
        self.assertEquals(result_attr, None)

    @patch('ldap.initialize')
    def test_that_perform_search_return_none_when_no_result(self, ldap_initialize):
        ldapobj = ldap_initialize.return_value = Mock()
        xivo_ldap = _XivoLDAP(self.config)
        ldapobj.search_ext_s.return_value = []

        result_dn, result_attr = xivo_ldap.perform_search('base', 'scope')
        self.assertEquals(result_dn, None)
        self.assertEquals(result_attr, None)
