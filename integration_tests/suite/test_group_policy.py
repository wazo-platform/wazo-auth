# Copyright 2017-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import uuid
from functools import partial

from hamcrest import (
    assert_that,
    contains_exactly,
    contains_inanyorder,
    empty,
    has_entries,
    has_item,
    has_items,
    not_,
)
from sqlalchemy import text

from .helpers import base, fixtures
from .helpers.base import SUB_TENANT_UUID
from .helpers.constants import ALL_USERS_POLICY_SLUG, UNKNOWN_SLUG, UNKNOWN_UUID

TENANT_UUID_1 = str(uuid.uuid4())


@base.use_asset('base')
class TestGroupPolicyAssociation(base.APIIntegrationTest):
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
            client.groups.add_policy(visible_group['uuid'], visible_policy['uuid'])
            base.assert_no_error(
                client.groups.remove_policy,
                visible_group['uuid'],
                visible_policy['uuid'],
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
        assert_that(result, has_entries(items=contains_exactly(policy1)))

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.group(tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(slug='top_shared', shared=True)
    def test_delete_with_shared(self, tenant, group, policy):
        self.client.groups.add_policy(group['uuid'], policy['uuid'])
        base.assert_no_error(
            self.client.groups.remove_policy,
            group['uuid'],
            policy['uuid'],
            tenant_uuid=SUB_TENANT_UUID,
        )
        self.client.groups.add_policy(group['uuid'], policy['slug'])
        base.assert_no_error(
            self.client.groups.remove_policy,
            group['uuid'],
            policy['slug'],
            tenant_uuid=SUB_TENANT_UUID,
        )

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
            assert_that(result, has_entries(items=contains_exactly(visible_policy)))

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
        assert_that(result, has_entries(items=contains_exactly(policy1)))

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.group(tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(slug='top_shared', shared=True)
    def test_put_with_shared(self, tenant, group, policy):
        self.client.groups.remove_policy(group['uuid'], policy['uuid'])
        base.assert_no_error(
            self.client.groups.add_policy,
            group['uuid'],
            policy['uuid'],
            tenant_uuid=SUB_TENANT_UUID,
        )
        self.client.groups.remove_policy(group['uuid'], policy['slug'])
        base.assert_no_error(
            self.client.groups.add_policy,
            group['uuid'],
            policy['slug'],
            tenant_uuid=SUB_TENANT_UUID,
        )

    @fixtures.http.user(username='foo')
    @fixtures.http.group()
    @fixtures.http.policy(acl=['authorized', '!forbid-access'])
    @fixtures.http.policy(acl=['authorized', 'unauthorized'])
    @fixtures.http.policy(acl=['auth.#', 'authorized', '!unauthorized'])
    def test_put_when_policy_has_more_access_than_token(
        self, login, group, policy1, policy2, user_policy
    ):
        user_client = self.make_auth_client('foo', login['password'])
        self.client.users.add_policy(login['uuid'], user_policy['uuid'])
        token = user_client.token.new(expiration=30)['token']
        user_client.set_token(token)

        base.assert_no_error(
            user_client.groups.add_policy,
            group['uuid'],
            policy1['uuid'],
        )
        base.assert_http_error(
            401,
            user_client.groups.add_policy,
            group['uuid'],
            policy2['uuid'],
        )

        result = self.client.groups.get_policies(group['uuid'])
        assert_that(result, has_entries(items=contains_exactly(policy1)))

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
        expected = contains_exactly(foo)
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

    @fixtures.http.tenant(uuid=TENANT_UUID_1)
    @fixtures.http.group(name='one', tenant_uuid=TENANT_UUID_1)
    @fixtures.http.policy(name='main', acl=['foobar'])
    @fixtures.http.user(username='foo', tenant_uuid=TENANT_UUID_1)
    def test_generated_acl(self, _, group, policy, user):
        self.client.groups.add_user(group['uuid'], user['uuid'])
        self.client.groups.add_policy(group['uuid'], policy['uuid'])

        user_client = self.asset_cls.make_auth_client('foo', user['password'])
        token_data = user_client.token.new('wazo_user', expiration=5)
        assert_that(token_data, has_entries(acl=has_items('foobar')))

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
        with self.database.connect() as connection:
            connection.execute(
                text(
                    f"DELETE FROM auth_policy_access WHERE policy_uuid = '{policy_uuid}'"
                )
            )

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.group(tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(slug='top_shared', shared=True)
    @fixtures.http.policy(slug='child', tenant_uuid=SUB_TENANT_UUID)
    def test_policy_list_with_shared(self, tenant, group, top_shared, child):
        self.client.groups.add_policy(group['uuid'], top_shared['uuid'])
        self.client.groups.add_policy(group['uuid'], child['uuid'])
        result = self.client.groups.get_policies(
            group['uuid'],
            tenant_uuid=SUB_TENANT_UUID,
        )
        assert_that(
            result,
            has_entries(
                total=2,
                filtered=2,
                items=contains_inanyorder(
                    has_entries(
                        slug='top_shared',
                        read_only=True,
                        tenant_uuid=group['tenant_uuid'],
                    ),
                    has_entries(
                        slug='child',
                        read_only=False,
                        tenant_uuid=group['tenant_uuid'],
                    ),
                ),
            ),
        )


@base.use_asset('base')
class TestGroupPolicySlug(base.APIIntegrationTest):
    @fixtures.http.group()
    @fixtures.http.policy()
    @fixtures.http.policy()
    def test_delete(self, group, policy1, policy2):
        self.client.groups.add_policy(group['uuid'], policy1['uuid'])
        self.client.groups.add_policy(group['uuid'], policy2['uuid'])

        url = self.client.groups.remove_policy
        base.assert_http_error(404, url, UNKNOWN_UUID, policy1['slug'])
        base.assert_http_error(404, url, group['uuid'], UNKNOWN_SLUG)
        base.assert_no_error(url, group['uuid'], policy2['slug'])

        result = self.client.groups.get_policies(group['uuid'])
        assert_that(result, has_entries(items=contains_exactly(policy1)))

    @fixtures.http.group()
    def test_delete_multi_tenant(self, group):
        with self.client_in_subtenant() as (client, _, __):
            policy_slug = 'policy_slug'
            client.policies.new(name=policy_slug, slug=policy_slug)
            visible_group = client.groups.new(name='group2')
            client.groups.add_policy(visible_group['uuid'], policy_slug)

            base.assert_http_error(
                404,
                client.groups.remove_policy,
                group['uuid'],
                policy_slug,
            )

            base.assert_http_error(
                404,
                self.client.groups.remove_policy,
                group['uuid'],
                policy_slug,
            )

            base.assert_no_error(
                client.groups.remove_policy,
                visible_group['uuid'],
                policy_slug,
            )
            result = client.groups.get_policies(visible_group['uuid'])
            assert_that(result, has_entries(items=empty()))

    @fixtures.http.group()
    @fixtures.http.policy()
    def test_put(self, group, policy):
        url = self.client.groups.add_policy
        base.assert_http_error(404, url, UNKNOWN_UUID, policy['slug'])
        base.assert_http_error(404, url, group['uuid'], UNKNOWN_SLUG)
        base.assert_no_error(url, group['uuid'], policy['slug'])

        result = self.client.groups.get_policies(group['uuid'])
        assert_that(result, has_entries(items=contains_exactly(policy)))

    @fixtures.http.group()
    def test_put_multi_tenant(self, group):
        with self.client_in_subtenant() as (client, _, __):
            policy_slug = 'policy_slug'
            visible_policy = client.policies.new(name=policy_slug, slug=policy_slug)
            visible_group = client.groups.new(name='group2')

            base.assert_http_error(
                404,
                client.groups.add_policy,
                group['uuid'],
                policy_slug,
            )

            base.assert_http_error(
                404,
                self.client.groups.add_policy,
                group['uuid'],
                policy_slug,
            )

            base.assert_no_error(
                client.groups.add_policy,
                visible_group['uuid'],
                policy_slug,
            )
            result = client.groups.get_policies(visible_group['uuid'])
            assert_that(result, has_entries(items=contains_exactly(visible_policy)))
