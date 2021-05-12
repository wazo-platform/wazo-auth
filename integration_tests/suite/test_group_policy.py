# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from functools import partial
from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    has_entries,
    has_items,
    has_item,
    not_,
)
from .helpers import base, fixtures
from .helpers.constants import UNKNOWN_UUID, ALL_USERS_POLICY_SLUG


class TestGroupPolicyAssociation(base.WazoAuthTestCase):
    @fixtures.http.group()
    @fixtures.http.policy()
    @fixtures.http.policy()
    def test_delete(self, group, policy1, policy2):
        self.client.groups.add_policy(group['uuid'], policy1['uuid'])
        self.client.groups.add_policy(group['uuid'], policy2['uuid'])

        with self.client_in_subtenant() as (client, _, __):
            visible_policy = client.policies.new(name='policy3')
            visible_group = client.groups.new(name='group2')

            # group not in client's sub-tenant tree
            self.client.groups.add_policy(group['uuid'], visible_policy['uuid'])
            base.assert_http_error(
                404, client.groups.remove_policy, group['uuid'], visible_policy['uuid']
            )

            # Any policies of a visible group can be removed.
            self.client.groups.add_policy(visible_group['uuid'], policy1['uuid'])
            base.assert_no_error(
                client.groups.remove_policy, visible_group['uuid'], policy1['uuid']
            )

        base.assert_http_error(
            404, self.client.groups.remove_policy, UNKNOWN_UUID, policy1['uuid']
        )
        base.assert_http_error(
            404, self.client.groups.remove_policy, group['uuid'], UNKNOWN_UUID
        )
        base.assert_no_error(
            self.client.groups.remove_policy, group['uuid'], policy2['uuid']
        )
        base.assert_no_error(
            self.client.groups.remove_policy, group['uuid'], policy2['uuid']
        )

        result = self.client.groups.get_policies(group['uuid'])
        assert_that(result, has_entries('items', contains(policy1)))

    @fixtures.http.group()
    @fixtures.http.policy()
    @fixtures.http.policy()
    def test_put(self, group, policy1, policy2):
        with self.client_in_subtenant() as (client, _, __):
            visible_group = client.groups.new(name='group2')
            visible_policy = client.policies.new(name='policy3')

            base.assert_no_error(
                client.groups.add_policy, visible_group['uuid'], visible_policy['uuid']
            )
            base.assert_http_error(
                404, client.groups.add_policy, group['uuid'], visible_policy['uuid']
            )
            base.assert_http_error(
                404, client.groups.add_policy, visible_group['uuid'], policy1['uuid']
            )

            result = client.groups.get_policies(visible_group['uuid'])
            assert_that(result, has_entries(items=contains(visible_policy)))

        base.assert_http_error(
            404, self.client.groups.add_policy, UNKNOWN_UUID, policy1['uuid']
        )
        base.assert_http_error(
            404, self.client.groups.add_policy, group['uuid'], UNKNOWN_UUID
        )
        base.assert_no_error(
            self.client.groups.add_policy, group['uuid'], policy1['uuid']
        )
        base.assert_no_error(
            self.client.groups.add_policy, group['uuid'], policy1['uuid']
        )  # Twice

        result = self.client.groups.get_policies(group['uuid'])
        assert_that(result, has_entries(items=contains(policy1)))

    @fixtures.http.group()
    @fixtures.http.policy(name='foo')
    @fixtures.http.policy(name='bar')
    @fixtures.http.policy(name='baz')
    @fixtures.http.policy(name='ignored')
    def test_list_policies(self, group, foo, bar, baz, ignored):
        for policy in (foo, bar, baz):
            self.client.groups.add_policy(group['uuid'], policy['uuid'])

        with self.client_in_subtenant() as (client, _, __):
            base.assert_http_error(404, client.groups.get_policies, group['uuid'])

        action = partial(self.client.groups.get_policies, group['uuid'])

        result = action()
        expected = contains_inanyorder(foo, bar, baz)
        assert_that(result, has_entries(total=3, filtered=3, items=expected))

        result = action(search='ba')
        expected = contains_inanyorder(bar, baz)
        assert_that(result, has_entries(total=3, filtered=2, items=expected))

        result = action(name='foo')
        expected = contains(foo)
        assert_that(result, has_entries(total=3, filtered=1, items=expected))

    @fixtures.http.group()
    @fixtures.http.policy(name='foo')
    @fixtures.http.policy(name='bar')
    def test_list_policies_sorting(self, group, foo, bar):
        for policy in (foo, bar):
            self.client.groups.add_policy(group['uuid'], policy['uuid'])

        action = partial(self.client.groups.get_policies, group['uuid'])
        expected = [bar, foo]
        base.assert_sorted(action, order='name', expected=expected)

    @fixtures.http.group()
    @fixtures.http.policy(name='foo')
    @fixtures.http.policy(name='bar')
    @fixtures.http.policy(name='baz')
    def test_list_policies_paginating(self, group, foo, bar, baz):
        for policy in (foo, bar, baz):
            self.client.groups.add_policy(group['uuid'], policy['uuid'])

        action = partial(self.client.groups.get_policies, group['uuid'])

        result = action(limit=1)
        expected = contains_inanyorder(bar)
        assert_that(result, has_entries(total=3, filtered=3, items=expected))

        result = action(offset=1)
        expected = contains_inanyorder(baz, foo)
        assert_that(result, has_entries(total=3, filtered=3, items=expected))

    @fixtures.http.group(name='one')
    @fixtures.http.policy(name='main', acl=['foobar'])
    @fixtures.http.user_register(username='foo', password='bar')
    def test_generated_acl(self, group, policy, user):
        self.client.groups.add_user(group['uuid'], user['uuid'])
        self.client.groups.add_policy(group['uuid'], policy['uuid'])

        user_client = self.new_auth_client('foo', 'bar')
        token_data = user_client.token.new('wazo_user', expiration=5)
        assert_that(token_data, has_entries('acl', has_items('foobar')))

    def test_default_policies_are_updated_at_startup(self):
        policy = self.client.policies.list(slug=ALL_USERS_POLICY_SLUG)['items'][0]
        self._remove_policy_acl(policy['uuid'])
        policy = self.client.policies.get(policy['uuid'])
        assert_that(policy, has_entries(acl=[]))

        self.restart_auth()

        policy = self.client.policies.get(policy['uuid'])
        assert_that(policy, has_entries(acl=has_item('integration_tests.access')))

    @fixtures.http.group()
    @fixtures.http.policy(name='kept', acl=['kept'], config_managed=True)
    def test_default_policies_are_not_deleted_when_associated(self, group, policy):
        self.client.groups.add_policy(group['uuid'], policy['uuid'])

        self.restart_auth()

        policies = self.client.groups.get_policies(group['uuid'])['items']
        assert_that(policies, has_item(has_entries(uuid=policy['uuid'])))

        policy = self.client.policies.get(policy['uuid'])
        assert_that(policy, has_entries(uuid=policy['uuid']))

    @fixtures.http.policy(name='to-be-removed', acl=['removed'], config_managed=True)
    def test_policies_are_deleted_at_startup(self, policy):
        group_name = f'wazo-all-users-tenant-{self.top_tenant_uuid}'
        group = self.client.groups.list(name=group_name)['items'][0]
        self.client.groups.add_policy(group['uuid'], policy['uuid'])

        self.restart_auth()

        # all_users_policies are dissociated
        policies = self.client.groups.get_policies(group['uuid'])['items']
        assert_that(policies, not_(has_item(has_entries(uuid=policy['uuid']))))

        # default_policies are removed
        base.assert_http_error(404, self.client.policies.get, policy['uuid'])

    def test_policies_are_created_and_associated_at_startup(self):
        group_name = f'wazo-all-users-tenant-{self.top_tenant_uuid}'
        group = self.client.groups.list(name=group_name)['items'][0]
        policy = self.client.policies.list(slug=ALL_USERS_POLICY_SLUG)['items'][0]
        self._remove_policy_acl(policy['uuid'])
        self.client.groups.remove_policy(group['uuid'], policy['uuid'])

        self.restart_auth()

        # default_policies are created
        policy = self.client.policies.get(policy['uuid'])
        assert_that(policy, has_entries(uuid=policy['uuid']))

        # all_users_policies are associated
        group_policies = self.client.groups.get_policies(group['uuid'])['items']
        assert_that(
            group_policies,
            has_item(
                has_entries(
                    name='wazo-all-users-policy',
                    acl=has_item('integration_tests.access'),
                )
            ),
        )

    def _remove_policy_acl(self, policy_uuid):
        with self.new_db_client().connect() as connection:
            connection.execute(
                f"DELETE FROM auth_policy_access WHERE policy_uuid = '{policy_uuid}'"
            )
