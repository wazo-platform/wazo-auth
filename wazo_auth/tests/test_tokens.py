# Copyright 2015-2020 The Wazo Authors  (see the AUTHORS file)
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
        self.pbx_user_uuid = new_uuid()
        self.xivo_uuid = new_uuid()
        self.session_uuid = new_uuid()
        self.issued_at = 1480011471.53537
        self.expires_at = 1480011513.53537
        self.acl = ['confd']
        self.metadata = {
            'uuid': self.pbx_user_uuid,
            'auth_id': self.auth_id,
            'pbx_user_uuid': self.pbx_user_uuid,
        }
        self.user_agent = 'user-agent'
        self.remote_addr = '192.168.1.1'

        self.token = token.Token(
            self.id_,
            auth_id=self.auth_id,
            pbx_user_uuid=self.pbx_user_uuid,
            xivo_uuid=self.xivo_uuid,
            issued_t=self.issued_at,
            expire_t=self.expires_at,
            acl=self.acl,
            metadata=self.metadata,
            session_uuid=self.session_uuid,
            user_agent=self.user_agent,
            remote_addr=self.remote_addr,
        )
        self.utc_issued_at = '2016-11-24T18:17:51.535370'
        self.utc_expires_at = '2016-11-24T18:18:33.535370'

    def test_matches_required_accesss_when_user_access_ends_with_hashtag(self):
        self.token.acl = ['foo.bar.#']

        assert_that(self.token.matches_required_access('foo.bar'), equal_to(False))
        assert_that(self.token.matches_required_access('foo.bar.toto'))
        assert_that(self.token.matches_required_access('foo.bar.toto.tata'))
        assert_that(
            self.token.matches_required_access('other.bar.toto'), equal_to(False)
        )

    def test_matches_required_accesss_when_user_access_has_not_special_character(self):
        self.token.acl = ['foo.bar.toto']

        assert_that(self.token.matches_required_access('foo.bar.toto'))
        assert_that(
            self.token.matches_required_access('foo.bar.toto.tata'), equal_to(False)
        )
        assert_that(
            self.token.matches_required_access('other.bar.toto'), equal_to(False)
        )

    def test_matches_required_accesss_when_user_access_has_asterisks(self):
        self.token.acl = ['foo.*.*']

        assert_that(self.token.matches_required_access('foo.bar.toto'))
        assert_that(
            self.token.matches_required_access('foo.bar.toto.tata'), equal_to(False)
        )
        assert_that(
            self.token.matches_required_access('other.bar.toto'), equal_to(False)
        )

    def test_matches_required_accesss_with_multiple_accesses(self):
        self.token.acl = ['foo', 'foo.bar.toto', 'other.#']

        assert_that(self.token.matches_required_access('foo'))
        assert_that(self.token.matches_required_access('foo.bar'), equal_to(False))
        assert_that(self.token.matches_required_access('foo.bar.toto'))
        assert_that(
            self.token.matches_required_access('foo.bar.toto.tata'), equal_to(False)
        )
        assert_that(self.token.matches_required_access('other.bar.toto'))

    def test_matches_required_accesss_when_user_access_has_hashtag_in_middle(self):
        self.token.acl = ['foo.bar.#.titi']

        assert_that(self.token.matches_required_access('foo.bar'), equal_to(False))
        assert_that(self.token.matches_required_access('foo.bar.toto'), equal_to(False))
        assert_that(
            self.token.matches_required_access('foo.bar.toto.tata'), equal_to(False)
        )
        assert_that(self.token.matches_required_access('foo.bar.toto.tata.titi'))

    def test_matches_required_accesss_when_user_access_ends_with_me(self):
        self.token.acl = ['foo.#.me']
        self.token.auth_id = '123'

        assert_that(self.token.matches_required_access('foo.bar'), equal_to(False))
        assert_that(self.token.matches_required_access('foo.bar.me'), equal_to(True))
        assert_that(self.token.matches_required_access('foo.bar.123'))
        assert_that(self.token.matches_required_access('foo.bar.toto.me'))
        assert_that(self.token.matches_required_access('foo.bar.toto.123'))
        assert_that(
            self.token.matches_required_access('foo.bar.toto.me.titi'), equal_to(False)
        )
        assert_that(
            self.token.matches_required_access('foo.bar.toto.123.titi'), equal_to(False)
        )

    def test_matches_required_accesss_when_user_access_has_me_in_middle(self):
        self.token.acl = ['foo.#.me.bar']
        self.token.auth_id = '123'

        assert_that(self.token.matches_required_access('foo.bar.123'), equal_to(False))
        assert_that(self.token.matches_required_access('foo.bar.me'), equal_to(False))
        assert_that(self.token.matches_required_access('foo.bar.123.bar'))
        assert_that(
            self.token.matches_required_access('foo.bar.me.bar'), equal_to(True)
        )
        assert_that(self.token.matches_required_access('foo.bar.toto.123.bar'))
        assert_that(self.token.matches_required_access('foo.bar.toto.me.bar'))

    def test_does_not_match_required_accesss_when_negating(self):
        self.token.acl = ['!foo.me.bar']

        assert_that(self.token.matches_required_access('foo.me.bar'), equal_to(False))

    def test_does_not_match_required_accesss_when_negating_multiple_identical_accesses(
        self,
    ):
        self.token.acl = ['foo.me.bar', '!foo.me.bar', 'foo.me.bar']

        assert_that(self.token.matches_required_access('foo.me.bar'), equal_to(False))

    def test_does_not_match_required_accesss_when_negating_ending_hashtag(self):
        self.token.acl = ['!foo.me.bar.#', 'foo.me.bar.123']

        assert_that(
            self.token.matches_required_access('foo.me.bar.123'), equal_to(False)
        )

    def test_does_not_match_required_accesss_when_negating_hashtag_sublevel(self):
        self.token.acl = ['foo.#', '!foo.me.bar.#', 'foo.me.bar.123']

        assert_that(
            self.token.matches_required_access('foo.me.bar.123'), equal_to(False)
        )

    def test_matches_required_access_when_negating_specific(self):
        self.token.acl = ['foo.*.bar', '!foo.123.bar']

        assert_that(self.token.matches_required_access('foo.me.bar'))
        assert_that(self.token.matches_required_access('foo.123.bar'), equal_to(False))

    def test_does_not_match_required_access_when_negating_toplevel(self):
        self.token.acl = ['!*.bar', 'foo.bar']

        assert_that(self.token.matches_required_access('foo.bar'), equal_to(False))

    def test_is_expired_when_time_is_in_the_future(self):
        self.token.expire_t = time.time() + 60

        self.assertFalse(self.token.is_expired())

    def test_is_expired_when_time_is_in_the_past(self):
        self.token.expire_t = time.time() - 60

        self.assertTrue(self.token.is_expired())

    def test_is_expired_when_no_expiration(self):
        self.token.expire_t = None

        self.assertFalse(self.token.is_expired())
