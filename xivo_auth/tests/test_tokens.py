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

from hamcrest import assert_that, equal_to
from mock import Mock, patch, sentinel

from xivo_auth import token, extensions, BaseAuthenticationBackend


class TestManager(unittest.TestCase):

    def setUp(self):
        self.config = {'default_token_lifetime': sentinel.default_expiration_delay}
        self.consul = Mock()
        self.consul_acl_generator = Mock(token._ConsulACLGenerator)
        extensions.celery = self.celery = Mock()
        self.manager = token.Manager(self.config, self.consul, self.celery, self.consul_acl_generator)

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
        assert_that(token.token, equal_to(self.consul.acl.create.return_value))
        mocked_later.assert_called_once_with(sentinel.default_expiration_delay)
        self.consul_acl_generator.create_from_backend.assert_called_once_with(backend, login, args)
        self.manager._push_token_data.assert_called_once_with(token)

    @patch('xivo_auth.token.later')
    def test_now_token_with_expiration(self, mocked_later):
        self.manager._push_token_data = Mock()
        backend = self._new_backend_mock()
        args = {'expiration': sentinel.expiration_delay}

        token = self.manager.new_token(backend, sentinel.login, args)

        assert_that(token.expires_at, equal_to(mocked_later.return_value))
        mocked_later.assert_called_once_with(sentinel.expiration_delay)

    def test_remove_token(self):
        token = 'my-token'
        self.manager._get_token_hash = Mock()

        self.manager.remove_token(token)

        self.celery.control.revoke.assert_called_once_with(self.manager._get_token_hash.return_value)
        self.consul.acl.destroy.assert_called_once_with(token)
        self.consul.kv.delete.assert_called_once_with('xivo/xivo-auth/tokens/{}'.format(token), recurse=True)


class TestToken(unittest.TestCase):

    def test_to_dict(self):
        t = token.Token('the-token', 'the-auth-id', None, 'now', 'later', ['acl:confd'])

        expected = {
            'token': 'the-token',
            'auth_id': 'the-auth-id',
            'issued_at': 'now',
            'expires_at': 'later',
            'xivo_user_uuid': None,
            'acls': {'acl:confd': 'acl:confd'},
        }
        assert_that(t.to_dict(), equal_to(expected))

    def test_to_dict_with_no_acl(self):
        t = token.Token('the-token', 'the-auth-id', None, 'now', 'later', [])

        expected = {
            'token': 'the-token',
            'auth_id': 'the-auth-id',
            'issued_at': 'now',
            'expires_at': 'later',
            'xivo_user_uuid': None,
            'acls': None,
        }
        assert_that(t.to_dict(), equal_to(expected))

    def test_from_dict(self):
        d = {'token': 'the-token',
             'auth_id': 'the-auth-id',
             'issued_at': 'now',
             'expires_at': 'later',
             'xivo_user_uuid': None,
             'acls': {'acl:confd': 'acl:confd'}}

        t = token.Token.from_dict(d)

        assert_that(t.token, equal_to('the-token'))
        assert_that(t.acls, equal_to(['acl:confd']))

    def test_from_dict_no_Acl(self):
        d = {'token': 'the-token',
             'auth_id': 'the-auth-id',
             'issued_at': 'now',
             'expires_at': 'later',
             'xivo_user_uuid': None,
             'acls': None}

        t = token.Token.from_dict(d)

        assert_that(t.token, equal_to('the-token'))
        assert_that(t.acls, equal_to([]))
