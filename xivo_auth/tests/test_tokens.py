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

import unittest

from hamcrest import assert_that, contains_inanyorder, equal_to, has_items, has_key, is_not, none
from mock import Mock, call, patch, sentinel

from xivo_auth import token, extensions, BaseAuthenticationBackend
from xivo_auth.helpers import later


class TestManager(unittest.TestCase):

    def setUp(self):
        self.config = {'default_token_lifetime': sentinel.default_expiration_delay}
        self.storage = Mock(token.Storage)
        self.consul_acl_generator = Mock(token._ConsulACLGenerator)
        extensions.celery = self.celery = Mock()
        self.manager = token.Manager(self.config, self.storage, self.celery, self.consul_acl_generator)

    def _new_backend_mock(self, auth_id=None, uuid=None):
        get_ids = Mock(return_value=(auth_id or sentinel.auth_id,
                                     uuid or sentinel.uuid))
        return Mock(BaseAuthenticationBackend, get_ids=get_ids)

    @patch('xivo_auth.token.now', Mock(return_value=sentinel.now))
    @patch('xivo_auth.token.later')
    def test_new_token(self, mocked_later):
        self.manager._push_token_data = Mock()
        backend = self._new_backend_mock()
        login = sentinel.login
        args = {}

        token = self.manager.new_token(backend, login, args)

        assert_that(token.auth_id, equal_to(sentinel.auth_id))
        assert_that(token.xivo_user_uuid, equal_to(sentinel.uuid))
        assert_that(token.issued_at, equal_to(sentinel.now))
        assert_that(token.expires_at, equal_to(mocked_later.return_value))
        mocked_later.assert_called_once_with(sentinel.default_expiration_delay)
        self.consul_acl_generator.create_from_backend.assert_called_once_with(backend, login, args)
        self.storage.put_token.assert_called_once_with(token, self.consul_acl_generator.create_from_backend.return_value)

    @patch('xivo_auth.token.later')
    def test_now_token_with_expiration(self, mocked_later):
        self.manager._push_token_data = Mock()
        backend = self._new_backend_mock()
        args = {'expiration': sentinel.expiration_delay}

        token = self.manager.new_token(backend, sentinel.login, args)

        assert_that(token.expires_at, equal_to(mocked_later.return_value))
        mocked_later.assert_called_once_with(sentinel.expiration_delay)

    def test_remove_token(self):
        token_id = 'my-token'
        self.manager._get_token_hash = Mock()

        self.manager.remove_token(token_id)

        self.celery.control.revoke.assert_called_once_with(self.manager._get_token_hash.return_value)
        self.storage.remove_token.assert_called_once_with(token_id)


class TestToken(unittest.TestCase):

    def test_to_consul(self):
        t = token.Token('the-token', 'the-auth-id', None, 'now', 'later', ['acl:confd'], 'the-name')

        expected = {
            'token': 'the-token',
            'auth_id': 'the-auth-id',
            'issued_at': 'now',
            'expires_at': 'later',
            'xivo_user_uuid': None,
            'acls': {'acl:confd': 'acl:confd'},
            'name': 'the-name',
        }
        assert_that(t.to_consul(), equal_to(expected))

    def test_to_consul_with_no_acl(self):
        t = token.Token('the-token', 'the-auth-id', None, 'now', 'later', [], 'the-name')

        expected = {
            'token': 'the-token',
            'auth_id': 'the-auth-id',
            'issued_at': 'now',
            'expires_at': 'later',
            'xivo_user_uuid': None,
            'acls': None,
            'name': 'the-name',
        }
        assert_that(t.to_consul(), equal_to(expected))

    def test_to_consul_with_no_name(self):
        t = token.Token('the-token', 'the-auth-id', None, 'now', 'later', [])

        assert_that(t.to_consul()['name'], none())

    def test_to_dict_doesnt_show_name(self):
        # token name is only used internally in XiVO, and it should not be part of xivo-auth
        # HTTP API until we have a good reason to do so
        t = token.Token('the-token', 'the-auth-id', None, 'now', 'later', [])

        assert_that(t.to_dict(), is_not(has_key('name')))

    def test_matches_required_acls(self):
        t = self._new_token(acls=['acl:foobar'])
        assert_that(t.matches_required_acl('acl:foobar'))
        assert_that(t.matches_required_acl('acl:other'), equal_to(False))

    def test_is_expired_when_time_is_in_the_future(self):
        time_in_the_future = later(60)
        t = self._new_token(expires_at=time_in_the_future)

        self.assertFalse(t.is_expired())

    def test_is_expired_when_time_is_in_the_past(self):
        time_in_the_past = later(-60)
        t = self._new_token(expires_at=time_in_the_past)

        self.assertTrue(t.is_expired())

    def test_is_expired_when_no_expiration(self):
        t = self._new_token(expires_at=None)

        self.assertFalse(t.is_expired())

    def _new_token(self, consul_token='the-token', auth_id='the-auth-id',
                   issued_at='now', expires_at='later',
                   xivo_user_uuid=None, acls=None):
        if not acls:
            acls = []

        return token.Token(consul_token, auth_id, xivo_user_uuid, issued_at, expires_at, acls)


class TestStorage(unittest.TestCase):

    def setUp(self):
        self.consul = Mock()
        self.storage = token.Storage(self.consul)

    def test_get_token(self):
        token_id = '12345678-1234-5678-1234-567812345678'
        self.consul.kv.get.return_value = (42, [
            {'Key': 'xivo/xivo-auth/tokens/12345678-1234-5678-1234-567812345678/token', 'Value': token_id},
            {'Key': 'xivo/xivo-auth/tokens/12345678-1234-5678-1234-567812345678/auth_id', 'Value': ''},
            {'Key': 'xivo/xivo-auth/tokens/12345678-1234-5678-1234-567812345678/xivo_user_uuid', 'Value': ''},
            {'Key': 'xivo/xivo-auth/tokens/12345678-1234-5678-1234-567812345678/issued_at', 'Value': ''},
            {'Key': 'xivo/xivo-auth/tokens/12345678-1234-5678-1234-567812345678/expires_at', 'Value': ''},
        ])

        token = self.storage.get_token(token_id)

        assert_that(token.token, equal_to(token_id))
        self.consul.kv.get.assert_called_once_with('xivo/xivo-auth/tokens/12345678-1234-5678-1234-567812345678', recurse=True)

    def test_put_token(self):
        t = token.Token(None, None, None, None, None, [], None)
        rules = None
        self.consul.acl.create.return_value = 'foo'

        self.storage.put_token(t, rules)

        assert_that(t.token, equal_to('foo'))
        self.consul.acl.create.assert_called_once_with(rules=rules)
        self.consul.kv.put.assert_any_call('xivo/xivo-auth/tokens/foo/token', 'foo')
        self.consul.kv.put.assert_any_call('xivo/xivo-auth/tokens/foo/auth_id', None)
        self.consul.kv.put.assert_any_call('xivo/xivo-auth/tokens/foo/xivo_user_uuid', None)
        self.consul.kv.put.assert_any_call('xivo/xivo-auth/tokens/foo/issued_at', None)
        self.consul.kv.put.assert_any_call('xivo/xivo-auth/tokens/foo/expires_at', None)
        self.consul.kv.put.assert_any_call('xivo/xivo-auth/tokens/foo/acls', None)
        self.consul.kv.put.assert_any_call('xivo/xivo-auth/tokens/foo/name', None)

    def test_put_token_with_name(self):
        t = token.Token(None, None, None, None, None, [], 'foo-name')
        rules = None
        self.consul.kv.get.return_value = (42, None)
        self.consul.acl.create.return_value = 'foo'

        self.storage.put_token(t, rules)

        assert_that(t.token, equal_to('foo'))
        self.consul.kv.get.assert_called_once_with('xivo/xivo-auth/token-names/foo-name')
        self.consul.kv.put.assert_any_call('xivo/xivo-auth/tokens/foo/token', 'foo')
        self.consul.kv.put.assert_any_call('xivo/xivo-auth/tokens/foo/name', 'foo-name')
        self.consul.kv.put.assert_any_call('xivo/xivo-auth/token-names/foo-name', 'foo')

    def test_put_token_with_id(self):
        t = token.Token('foo', None, None, None, None, [], None)
        rules = None
        self.consul.kv.get.return_value = (42, None)

        self.storage.put_token(t, rules)

        assert_that(t.token, equal_to('foo'))
        self.consul.acl.update.assert_called_once_with('foo', rules=rules)
        self.consul.kv.put.assert_any_call('xivo/xivo-auth/tokens/foo/token', 'foo')

    def test_put_token_with_name_and_indexed_id(self):
        t = token.Token(None, None, None, None, None, [], 'foo-name')
        rules = None
        self.consul.kv.get.return_value = (42, {'Value': 'foo'})

        self.storage.put_token(t, None)

        assert_that(t.token, equal_to('foo'))
        self.consul.acl.update.assert_called_once_with('foo', rules=rules)
        self.consul.kv.put.assert_any_call('xivo/xivo-auth/token-names/foo-name', 'foo')

    def test_remove_token(self):
        token_id = '12345678-1234-5678-1234-567812345678'
        self.consul.kv.get.return_value = (42, None)

        self.storage.remove_token(token_id)

        self.consul.kv.get.assert_called_once_with('xivo/xivo-auth/tokens/12345678-1234-5678-1234-567812345678/name')
        self.consul.acl.destroy.assert_called_once_with('12345678-1234-5678-1234-567812345678')
        self.consul.kv.delete.assert_called_once_with('xivo/xivo-auth/tokens/12345678-1234-5678-1234-567812345678', recurse=True)

    def test_remove_named_token(self):
        token_id = '12345678-1234-5678-1234-567812345678'
        token_name = 'foo-name'
        self.consul.kv.get.return_value = (42, {'Value': token_name})

        self.storage.remove_token(token_id)

        self.consul.acl.destroy.assert_called_once_with('12345678-1234-5678-1234-567812345678')
        self.consul.kv.delete.assert_any_call('xivo/xivo-auth/tokens/12345678-1234-5678-1234-567812345678', recurse=True)
        self.consul.kv.delete.assert_any_call('xivo/xivo-auth/token-names/foo-name')
