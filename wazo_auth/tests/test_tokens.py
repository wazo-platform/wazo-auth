# Copyright 2015-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time
import unittest
import uuid

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

    def test_is_expired_when_time_is_in_the_future(self):
        self.token.expire_t = time.time() + 60

        self.assertFalse(self.token.is_expired())

    def test_is_expired_when_time_is_in_the_past(self):
        self.token.expire_t = time.time() - 60

        self.assertTrue(self.token.is_expired())

    def test_is_expired_when_no_expiration(self):
        self.token.expire_t = None

        self.assertFalse(self.token.is_expired())
