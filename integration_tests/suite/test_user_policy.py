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
from .helpers import fixtures, base
from .helpers.base import assert_http_error, assert_no_error
from .helpers.constants import UNKNOWN_SLUG, UNKNOWN_UUID


@base.use_asset('base')
class TestUsers(base.APIIntegrationTest):
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

    @fixtures.http.user(username='foo', password='bar')
    @fixtures.http.user()
    @fixtures.http.policy(acl=['authorized'])
    @fixtures.http.policy(acl=['authorized', 'unauthorized'])
    def test_put_when_policy_has_more_access_than_token(
        self, login, user, policy1, policy2
    ):
        user_client = self.make_auth_client('foo', 'bar')
        acl = ['auth.#', 'authorized', '!unauthorized']
        user_policy = self.client.policies.new(name='foo-policy', acl=acl)
        self.client.users.add_policy(login['uuid'], user_policy['uuid'])
        token = user_client.token.new(expiration=30)['token']
        user_client.set_token(token)

        assert_no_error(
            user_client.users.add_policy,
            user['uuid'],
            policy1['uuid'],
        )
        assert_http_error(
            401,
            user_client.users.add_policy,
            user['uuid'],
            policy2['uuid'],
        )

        result = self.client.users.get_policies(user['uuid'])
        assert_that(result, has_entries(items=contains(policy1)))

        self.client.policies.delete(user_policy['uuid'])


@base.use_asset('base')
class TestUserPolicySlug(base.APIIntegrationTest):
    @fixtures.http.user()
    @fixtures.http.policy()
    @fixtures.http.policy()
    def test_delete(self, user, policy1, policy2):
        self.client.users.add_policy(user['uuid'], policy1['uuid'])
        self.client.users.add_policy(user['uuid'], policy2['uuid'])

        url = self.client.users.remove_policy
        assert_http_error(404, url, UNKNOWN_UUID, policy1['slug'])
        assert_http_error(404, url, user['uuid'], UNKNOWN_SLUG)
        assert_no_error(url, user['uuid'], policy2['slug'])

        result = self.client.users.get_policies(user['uuid'])
        assert_that(result, has_entries('items', contains(policy1)))

    @fixtures.http.user()
    def test_delete_multi_tenant(self, user):
        with self.client_in_subtenant() as (client, _, __):
            policy_slug = 'policy_slug'
            client.policies.new(name=policy_slug, slug=policy_slug)
            visible_user = client.users.new(username='user2')
            client.users.add_policy(visible_user['uuid'], policy_slug)

            # FIXME: dissociation is not multi-tenant with user
            # assert_http_error(
            #     404,
            #     client.users.remove_policy,
            #     user['uuid'],
            #     policy_slug,
            # )

            assert_http_error(
                404,
                self.client.users.remove_policy,
                user['uuid'],
                policy_slug,
            )

            assert_no_error(
                client.users.remove_policy,
                visible_user['uuid'],
                policy_slug,
            )
            result = client.users.get_policies(visible_user['uuid'])
            assert_that(result, has_entries(items=empty()))

    @fixtures.http.user()
    @fixtures.http.policy()
    def test_put(self, user, policy):
        url = self.client.users.add_policy
        assert_http_error(404, url, UNKNOWN_UUID, policy['slug'])
        assert_http_error(404, url, user['uuid'], UNKNOWN_SLUG)
        assert_no_error(url, user['uuid'], policy['slug'])

        result = self.client.users.get_policies(user['uuid'])
        assert_that(result, has_entries(items=contains(policy)))

    @fixtures.http.user()
    def test_put_multi_tenant(self, user):
        with self.client_in_subtenant() as (client, _, __):
            policy_slug = 'policy_slug'
            visible_policy = client.policies.new(name=policy_slug, slug=policy_slug)
            visible_user = client.users.new(username='user2')

            # FIXME: association is not multi-tenant with user
            # assert_http_error(
            #     404,
            #     client.users.add_policy,
            #     user['uuid'],
            #     policy_slug,
            # )

            assert_http_error(
                404,
                self.client.users.add_policy,
                user['uuid'],
                policy_slug,
            )

            assert_no_error(
                client.users.add_policy,
                visible_user['uuid'],
                policy_slug,
            )
            result = client.users.get_policies(visible_user['uuid'])
            assert_that(result, has_entries(items=contains(visible_policy)))
