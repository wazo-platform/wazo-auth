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
import json
import uuid

from hamcrest import assert_that, contains_inanyorder, equal_to
from mock import ANY, Mock, patch, sentinel

from xivo_auth import token, extensions, BaseAuthenticationBackend
from xivo_auth.helpers import later


class AnyUUID(object):

    def __eq__(self, other):
        try:
            uuid.UUID(other)
            return True
        except ValueError:
            return False

    def __ne__(self, other):
        return not self == other


ANY_UUID = AnyUUID()


class TestManager(unittest.TestCase):

    def setUp(self):
        self.config = {'default_token_lifetime': sentinel.default_expiration_delay}
        self.storage = Mock(token.Storage)
        extensions.celery = self.celery = Mock()
        self.manager = token.Manager(self.config, self.storage, self.celery)

    def _new_backend_mock(self, auth_id=None, uuid=None):
        get_ids = Mock(return_value=(auth_id or sentinel.auth_id,
                                     uuid or sentinel.uuid))
        return Mock(BaseAuthenticationBackend, get_ids=get_ids)

    @patch('xivo_auth.token.now', Mock(return_value=sentinel.now))
    @patch('xivo_auth.token.later')
    def test_new_token(self, mocked_later):
        backend = self._new_backend_mock()
        login = sentinel.login
        args = {}

        self.manager.new_token(backend, login, args)

        token_payload = self.storage.create_token.call_args[0][0]
        assert_that(token_payload.auth_id, equal_to(sentinel.auth_id))
        assert_that(token_payload.xivo_user_uuid, equal_to(sentinel.uuid))
        assert_that(token_payload.issued_at, equal_to(sentinel.now))
        assert_that(token_payload.expires_at, equal_to(mocked_later.return_value))
        mocked_later.assert_called_once_with(sentinel.default_expiration_delay)
        self.storage.create_token.assert_called_once_with(ANY)

    @patch('xivo_auth.token.later')
    def test_now_token_with_expiration(self, mocked_later):
        backend = self._new_backend_mock()
        args = {'expiration': sentinel.expiration_delay}

        self.manager.new_token(backend, sentinel.login, args)

        token_payload = self.storage.create_token.call_args[0][0]
        assert_that(token_payload.expires_at, equal_to(mocked_later.return_value))
        mocked_later.assert_called_once_with(sentinel.expiration_delay)

    def test_remove_token(self):
        token_id = 'my-token'
        self.manager._get_token_hash = Mock()

        self.manager.remove_token(token_id)

        self.celery.control.revoke.assert_called_once_with(self.manager._get_token_hash.return_value)
        self.storage.remove_token.assert_called_once_with(token_id)


class TestToken(unittest.TestCase):

    def setUp(self):
        self.id_ = 'the-token-id'
        self.auth_id = 'the-auth-id'
        self.xivo_user_uuid = 'the-user-uuid'
        self.issued_at = 'the-issued-at'
        self.expires_at = 'the-expires-at'
        self.acls = ['confd']
        self.token = token.Token(self.id_, self.auth_id, self.xivo_user_uuid,
                                 self.issued_at, self.expires_at, self.acls)

    def test_to_consul(self):
        expected = {
            'token': self.id_,
            'auth_id': self.auth_id,
            'issued_at': self.issued_at,
            'expires_at': self.expires_at,
            'xivo_user_uuid': self.xivo_user_uuid,
            'acls': ['confd'],
        }

        assert_that(self.token.to_consul(), equal_to(expected))

    def test_matches_required_acls_when_user_acl_ends_with_hashtag(self):
        self.token.acls = ['foo.bar.#']

        assert_that(self.token.matches_required_acl('foo.bar'), equal_to(False))
        assert_that(self.token.matches_required_acl('foo.bar.toto'))
        assert_that(self.token.matches_required_acl('foo.bar.toto.tata'))
        assert_that(self.token.matches_required_acl('other.bar.toto'), equal_to(False))

    def test_matches_required_acls_when_user_acl_has_not_special_character(self):
        self.token.acls = ['foo.bar.toto']

        assert_that(self.token.matches_required_acl('foo.bar.toto'))
        assert_that(self.token.matches_required_acl('foo.bar.toto.tata'), equal_to(False))
        assert_that(self.token.matches_required_acl('other.bar.toto'), equal_to(False))

    def test_matches_required_acls_when_user_acl_has_asterisks(self):
        self.token.acls = ['foo.*.*']

        assert_that(self.token.matches_required_acl('foo.bar.toto'))
        assert_that(self.token.matches_required_acl('foo.bar.toto.tata'), equal_to(False))
        assert_that(self.token.matches_required_acl('other.bar.toto'), equal_to(False))

    def test_matches_required_acls_with_multiple_acls(self):
        self.token.acls = ['foo', 'foo.bar.toto', 'other.#']

        assert_that(self.token.matches_required_acl('foo'))
        assert_that(self.token.matches_required_acl('foo.bar'), equal_to(False))
        assert_that(self.token.matches_required_acl('foo.bar.toto'))
        assert_that(self.token.matches_required_acl('foo.bar.toto.tata'), equal_to(False))
        assert_that(self.token.matches_required_acl('other.bar.toto'))

    def test_matches_required_acls_when_user_acl_has_hashtag_in_middle(self):
        self.token.acls = ['foo.bar.#.titi']

        assert_that(self.token.matches_required_acl('foo.bar'), equal_to(False))
        assert_that(self.token.matches_required_acl('foo.bar.toto'), equal_to(False))
        assert_that(self.token.matches_required_acl('foo.bar.toto.tata'), equal_to(False))
        assert_that(self.token.matches_required_acl('foo.bar.toto.tata.titi'))

    def test_matches_required_acls_when_user_acl_ends_with_me(self):
        self.token.acls = ['foo.#.me']
        self.token.auth_id = '123'

        assert_that(self.token.matches_required_acl('foo.bar'), equal_to(False))
        assert_that(self.token.matches_required_acl('foo.bar.123'))
        assert_that(self.token.matches_required_acl('foo.bar.toto.123'))
        assert_that(self.token.matches_required_acl('foo.bar.toto.123.titi'), equal_to(False))

    def test_matches_required_acls_when_user_acl_has_me_in_middle(self):
        self.token.acls = ['foo.#.me.bar']
        self.token.auth_id = '123'

        assert_that(self.token.matches_required_acl('foo.bar.me.bar'), equal_to(False))
        assert_that(self.token.matches_required_acl('foo.bar.123'), equal_to(False))
        assert_that(self.token.matches_required_acl('foo.bar.123.bar'))
        assert_that(self.token.matches_required_acl('foo.bar.toto.123.bar'))

    def test_is_expired_when_time_is_in_the_future(self):
        time_in_the_future = later(60)
        self.token.expires_at = time_in_the_future

        self.assertFalse(self.token.is_expired())

    def test_is_expired_when_time_is_in_the_past(self):
        time_in_the_past = later(-60)
        self.token.expires_at = time_in_the_past

        self.assertTrue(self.token.is_expired())

    def test_is_expired_when_no_expiration(self):
        self.token.expires_at = None

        self.assertFalse(self.token.is_expired())


class TestStorage(unittest.TestCase):

    def setUp(self):
        self.token_id = 'tok-id'
        self.auth_id = 'the-auth-id'
        self.issued_at = 'the-issued-at'
        self.rules = None
        self.consul = Mock()
        self.storage = token.Storage(self.consul)

    def test_get_token(self):
        token_id = '12345678-1234-5678-1234-567812345678'
        raw_token = json.dumps({'token': token_id,
                                'auth_id': '',
                                'xivo_user_uuid': '',
                                'issued_at': '',
                                'expires_at': '',
                                'acls': []})
        self.consul.kv.get.return_value = 42, {'Key': 'xivo/xivo-auth/tokens/12345678-1234-5678-1234-567812345678',
                                               'Value': raw_token}

        token = self.storage.get_token(token_id)

        assert_that(token.token, equal_to(token_id))
        self.consul.kv.get.assert_called_once_with('xivo/xivo-auth/tokens/12345678-1234-5678-1234-567812345678')

    def test_create_token(self):
        token_payload = token.TokenPayload(self.auth_id, issued_at=self.issued_at)

        t = self.storage.create_token(token_payload)

        assert_that(t.token, equal_to(ANY_UUID))
        expected = {'token': t.token,
                    'auth_id': self.auth_id,
                    'xivo_user_uuid': None,
                    'issued_at': self.issued_at,
                    'expires_at': None,
                    'acls': []}
        self.assert_kv_put_json('xivo/xivo-auth/tokens/{}'.format(t.token), expected)

    def test_remove_token(self):
        token_id = '12345678-1234-5678-1234-567812345678'
        self.consul.kv.get.return_value = (42, None)

        self.storage.remove_token(token_id)

        self.consul.kv.delete.assert_called_once_with('xivo/xivo-auth/tokens/12345678-1234-5678-1234-567812345678',
                                                      recurse=True)

    def assert_kv_put_json(self, expected_path, expected_value):
        raw_calls = self.consul.kv.put.call_args_list
        calls = [(path, json.loads(value)) for path, value in [args for args, kwargs in raw_calls]]
        print 'Calls', calls
        print 'Expected', expected_value
        assert_that(calls, contains_inanyorder((expected_path, expected_value)))
