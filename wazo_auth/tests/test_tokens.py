# Copyright 2015-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
import time
import uuid

from hamcrest import assert_that, equal_to

from wazo_auth import token


def new_uuid():
    return str(uuid.uuid4())


class TestToken(unittest.TestCase):

    def setUp(self):
        self.id_ = new_uuid()
        self.auth_id = 'the-auth-id'
        self.xivo_user_uuid = new_uuid()
        self.xivo_uuid = new_uuid()
        self.session_uuid = new_uuid()
        self.issued_at = 1480011471.53537
        self.expires_at = 1480011513.53537
        self.acls = ['confd']
        self.metadata = {
            'uuid': self.xivo_user_uuid,
            'auth_id': self.auth_id,
            'xivo_user_uuid': self.xivo_user_uuid,
        }

        self.token = token.Token(
            self.id_,
            auth_id=self.auth_id,
            xivo_user_uuid=self.xivo_user_uuid,
            xivo_uuid=self.xivo_uuid,
            issued_t=self.issued_at,
            expire_t=self.expires_at,
            acls=self.acls,
            metadata=self.metadata,
            session_uuid=self.session_uuid,
        )
        self.utc_issued_at = '2016-11-24T18:17:51.535370'
        self.utc_expires_at = '2016-11-24T18:18:33.535370'

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
        assert_that(self.token.matches_required_acl('foo.bar.me'), equal_to(True))
        assert_that(self.token.matches_required_acl('foo.bar.123'))
        assert_that(self.token.matches_required_acl('foo.bar.toto.me'))
        assert_that(self.token.matches_required_acl('foo.bar.toto.123'))
        assert_that(self.token.matches_required_acl('foo.bar.toto.me.titi'), equal_to(False))
        assert_that(self.token.matches_required_acl('foo.bar.toto.123.titi'), equal_to(False))

    def test_matches_required_acls_when_user_acl_has_me_in_middle(self):
        self.token.acls = ['foo.#.me.bar']
        self.token.auth_id = '123'

        assert_that(self.token.matches_required_acl('foo.bar.123'), equal_to(False))
        assert_that(self.token.matches_required_acl('foo.bar.me'), equal_to(False))
        assert_that(self.token.matches_required_acl('foo.bar.123.bar'))
        assert_that(self.token.matches_required_acl('foo.bar.me.bar'), equal_to(True))
        assert_that(self.token.matches_required_acl('foo.bar.toto.123.bar'))
        assert_that(self.token.matches_required_acl('foo.bar.toto.me.bar'))

    def test_is_expired_when_time_is_in_the_future(self):
        self.token.expire_t = time.time() + 60

        self.assertFalse(self.token.is_expired())

    def test_is_expired_when_time_is_in_the_past(self):
        self.token.expire_t = time.time() - 60

        self.assertTrue(self.token.is_expired())

    def test_is_expired_when_no_expiration(self):
        self.token.expire_t = None

        self.assertFalse(self.token.is_expired())
