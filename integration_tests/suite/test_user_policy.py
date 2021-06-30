# Copyright 2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import requests
from hamcrest import (
    assert_that,
    calling,
    contains,
    empty,
    has_entries,
    has_properties,
)
from xivo_test_helpers.hamcrest.raises import raises
from .helpers import fixtures
from .helpers.base import assert_http_error, assert_no_error, WazoAuthTestCase


class TestUsers(WazoAuthTestCase):
    @fixtures.http.user_register(username='foo', password='bar')
    @fixtures.http.policy(name='one', acl=['this.is.a.test.access'])
    @fixtures.http.policy(name='two', acl=['acl.one', 'acl.two'])
    def test_user_policy(self, user, policy_1, policy_2):
        assert_no_error(self.client.users.remove_policy, user['uuid'], policy_1['uuid'])

        result = self.client.users.get_policies(user['uuid'])
        assert_that(
            result,
            has_entries(total=0, items=empty(), filtered=0),
            'not associated',
        )

        self.client.users.add_policy(user['uuid'], policy_1['uuid'])
        self.client.users.add_policy(user['uuid'], policy_2['uuid'])

        self.client.users.remove_policy(user['uuid'], policy_2['uuid'])

        assert_that(
            calling(self.client.users.add_policy).with_args(
                '8ee4e6a3-533e-4b00-99b2-33b2e55102f2', policy_2['uuid']
            ),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 404))
            ),
            'unknown user',
        )

        assert_that(
            calling(self.client.users.add_policy).with_args(
                user['uuid'], '113bb403-7914-4685-a0ec-330676e61f7c'
            ),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 404))
            ),
            'unknown policy',
        )

        result = self.client.users.get_policies(user['uuid'])
        assert_that(
            result,
            has_entries(total=1, items=contains(has_entries(name='one')), filtered=1),
            'not associated',
        )

        result = self.client.users.get_policies(user['uuid'], search='two')
        assert_that(
            result,
            has_entries(total=1, items=empty(), filtered=0),
            'not associated',
        )

        assert_no_error(self.client.users.remove_policy, user['uuid'], policy_1['uuid'])

    @fixtures.http.user()
    @fixtures.http.policy(acl=['authorized'])
    @fixtures.http.policy(acl=['authorized', 'unauthorized'])
    def test_put_when_policy_has_more_access_than_token(self, user, policy1, policy2):
        assert_no_error(self.client.users.add_policy, user['uuid'], policy1['uuid'])
        assert_http_error(
            401,
            self.client.users.add_policy,
            user['uuid'],
            policy2['uuid'],
        )

        result = self.client.users.get_policies(user['uuid'])
        assert_that(result, has_entries(items=contains(policy1)))
