# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import requests
from functools import partial
from hamcrest import (
    all_of,
    assert_that,
    contains,
    contains_inanyorder,
    empty,
    equal_to,
    has_entries,
    has_item,
    has_items,
    none,
    not_,
)
from mock import ANY
from wazo_test_helpers.hamcrest.uuid_ import uuid_
from .helpers import base
from .helpers.base import (
    assert_no_error,
    assert_http_error,
    assert_sorted,
    SUB_TENANT_UUID,
)
from .helpers import fixtures
from .helpers.constants import (
    UNKNOWN_UUID,
    UNKNOWN_SLUG,
    NB_DEFAULT_POLICIES,
    ALL_USERS_POLICY_SLUG,
)


@base.use_asset('base')
class TestPolicies(base.APIIntegrationTest):
    @fixtures.http.tenant()
    @fixtures.http.policy(name='foobaz')
    def test_post(self, tenant, foobaz):
        assert_that(
            foobaz,
            has_entries(
                uuid=uuid_(),
                name='foobaz',
                slug='foobaz',
                description=none(),
                acl=empty(),
                shared=False,
                tenant_uuid=self.top_tenant_uuid,
            ),
        )

        policy_args = {
            'name': 'foobar',
            'slug': 'slug1',
            'description': 'a test policy',
            'acl': ['dird.me.#', 'ctid-ng.#'],
            'shared': False,
            'tenant_uuid': tenant['uuid'],
        }
        # Specify the tenant_uuid
        with self.policy(self.client, **policy_args) as policy:
            assert_that(policy, has_entries(uuid=uuid_(), name='foobar'))

        # Specify the tenant uuid in another sub-tenant tree
        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(401, client.policies.new, **policy_args)

        # Invalid body
        assert_http_error(400, self.client.policies.new, '')

    def test_post_errors(self):
        bodies = [
            {'foo': 'bar'},
            42,
            True,
            False,
            None,
            'string',
            [{'list': 'dict'}],
            [42],
            ['#', False],
            [None],
        ]

        url = f'http://{self.auth_host}:{self.auth_port}/0.1/policies'
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Auth-Token': self.admin_token,
        }

        for body in bodies:
            response = requests.post(url, headers=headers, data=json.dumps(body))
            assert_that(response.status_code, equal_to(400))
            assert_that(
                response.json(),
                has_entries(
                    timestamp=contains(ANY), reason=contains(ANY), status_code=400
                ),
            )

        names = [None, True, False, '', 42]
        for name in names:
            body = {'name': name}
            response = requests.post(
                url, headers=headers, data=json.dumps(body), verify=False
            )
            assert_that(response.status_code, equal_to(400))
            assert_that(
                response.json(),
                has_entries(
                    timestamp=contains(ANY),
                    reason=contains('Invalid value supplied for field: name'),
                    status_code=400,
                ),
            )

        descriptions = [True, False, 42]
        for description in descriptions:
            body = {'name': 'name', 'description': description}
            response = requests.post(
                url, headers=headers, data=json.dumps(body), verify=False
            )
            assert_that(response.status_code, equal_to(400))
            assert_that(
                response.json(),
                has_entries(
                    timestamp=contains(ANY),
                    reason=contains('Invalid value supplied for field: description'),
                    status_code=400,
                ),
            )

    @fixtures.http.policy(slug='dup')
    def test_post_duplicate_slug(self, a):
        assert_http_error(409, self.client.policies.new, name='dup', slug='dup')

    @fixtures.http.policy(slug='top', shared=True)
    def test_post_duplicate_slug_when_top_shared(self, policy):
        parent_uuid = policy['tenant_uuid']
        with self.client_in_subtenant(parent_uuid=parent_uuid) as (client, _, tenant):
            assert_http_error(409, client.policies.new, name='top', slug='top')

    def test_post_duplicate_slug_shared_when_child_exists(self):
        args = {'name': 'child', 'slug': 'child'}
        with self.client_in_subtenant() as (client, _, tenant):
            client.policies.new(**args)
            assert_http_error(409, self.client.policies.new, shared=True, **args)
            assert_no_error(self.client.policies.new, shared=False, **args)
        self.client.policies.delete(args['slug'])

    @fixtures.http.user(username='foo', password='bar')
    def test_post_when_policy_has_more_access_than_token(self, user):
        user_client = self.make_auth_client('foo', 'bar')
        acl = ['auth.#', 'authorized', '!unauthorized']
        user_policy = self.client.policies.new(name='foo-policy', acl=acl)
        self.client.users.add_policy(user['uuid'], user_policy['uuid'])
        token = user_client.token.new(expiration=30)['token']
        user_client.set_token(token)

        policy_args = {
            'name': 'not-authorized',
            'acl': ['authorized', 'unauthorized'],
        }
        assert_http_error(401, user_client.policies.new, **policy_args)

        policy_args = {
            'name': 'authorized',
            'acl': ['authorized', '!forbid-access'],
        }
        policy = user_client.policies.new(**policy_args)
        assert_that(policy, has_entries(**policy_args))

        self.client.policies.delete(policy['uuid'])
        self.client.policies.delete(user_policy['uuid'])

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='one', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='two', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='three', tenant_uuid=SUB_TENANT_UUID)
    def test_list_sorting(self, _, one, two, three):
        action = partial(self.client.policies.list, tenant_uuid=SUB_TENANT_UUID)
        autocreated_policy = self.client.policies.list(
            read_only=True,
            tenant_uuid=SUB_TENANT_UUID,
            order='name',
        )['items']
        expected = [one, three, two, *autocreated_policy]
        assert_sorted(action, order='name', expected=expected)

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='one', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='two', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='three', tenant_uuid=SUB_TENANT_UUID)
    def test_list_tenant_filtering(self, _, one, two, three):
        # Different tenant
        response = self.client.policies.list(tenant_uuid=self.top_tenant_uuid)
        assert_that(response, has_entries(items=not_(has_items(one, two, three))))

        # Different tenant with recurse
        response = self.client.policies.list(
            recurse=True, tenant_uuid=self.top_tenant_uuid
        )
        expected_default = has_entries(
            slug=ALL_USERS_POLICY_SLUG,
            tenant_uuid=self.top_tenant_uuid,
        )
        assert_that(
            response,
            has_entries(items=has_items(one, two, three, expected_default)),
        )

        # Same tenant
        response = self.client.policies.list(tenant_uuid=SUB_TENANT_UUID)
        expected_default = has_entries(
            slug=ALL_USERS_POLICY_SLUG,
            tenant_uuid=SUB_TENANT_UUID,
        )
        assert_that(
            response,
            has_entries(
                total=3 + NB_DEFAULT_POLICIES,
                items=has_items(one, two, three, expected_default),
            ),
        )

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='one', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='two', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='three', tenant_uuid=SUB_TENANT_UUID)
    def test_list_searching(self, _, one, two, three):
        response = self.client.policies.list(tenant_uuid=SUB_TENANT_UUID, search='one')
        assert_that(
            response,
            has_entries(
                total=3 + NB_DEFAULT_POLICIES,
                items=contains(one),
            ),
        )

        response = self.client.policies.list(
            tenant_uuid=SUB_TENANT_UUID, read_only=False
        )
        assert_that(
            response,
            has_entries(
                total=3 + NB_DEFAULT_POLICIES,
                items=contains_inanyorder(one, two, three),
            ),
        )

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='one', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='two', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='three', tenant_uuid=SUB_TENANT_UUID)
    def test_list_paginating(self, _, one, two, three):
        response = self.client.policies.list(
            tenant_uuid=SUB_TENANT_UUID, order='name', limit=1
        )
        assert_that(
            response, has_entries(total=3 + NB_DEFAULT_POLICIES, items=contains(one))
        )

        response = self.client.policies.list(
            tenant_uuid=SUB_TENANT_UUID, order='name', offset=1
        )
        assert_that(
            response,
            has_entries(
                total=3 + NB_DEFAULT_POLICIES,
                items=all_of(has_items(two, three), not_(has_item(one))),
            ),
        )

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(slug='policy', shared=True, tenant_uuid=SUB_TENANT_UUID)
    def test_list_when_shared(self, _, policy):
        response = self.client.policies.list(tenant_uuid=SUB_TENANT_UUID)
        assert_that(
            response,
            has_entries(
                total=1 + NB_DEFAULT_POLICIES,
                items=has_items(
                    has_entries(
                        slug='policy',
                        read_only=False,
                        shared=True,
                        tenant_uuid=policy['tenant_uuid'],
                    )
                ),
            ),
        )

        parent_uuid = SUB_TENANT_UUID
        with self.client_in_subtenant(parent_uuid=parent_uuid) as (client, _, tenant):
            response = client.policies.list()
            assert_that(
                response,
                has_entries(
                    total=1 + NB_DEFAULT_POLICIES,
                    items=has_items(
                        has_entries(
                            slug='policy',
                            read_only=True,
                            shared=False,
                            tenant_uuid=tenant['uuid'],
                        )
                    ),
                ),
            )

    @fixtures.http.group()
    @fixtures.http.group()
    @fixtures.http.user()
    @fixtures.http.user()
    @fixtures.http.policy(
        name='foobar',
        description='a test policy',
        acl=['service1.me.#', 'service2.#'],
    )
    def test_get(self, group1, group2, user1, user2, policy):
        response = self.client.policies.get(policy['uuid'])
        assert_that(
            response,
            has_entries(
                name='foobar',
                description='a test policy',
                acl=contains_inanyorder('service1.me.#', 'service2.#'),
                read_only=False,
            ),
        )

        assert_http_error(404, self.client.policies.get, UNKNOWN_UUID)

        self.client.users.add_policy(user1['uuid'], policy['uuid'])
        self.client.users.add_policy(user2['uuid'], policy['uuid'])
        self.client.groups.add_policy(group1['uuid'], policy['uuid'])
        self.client.groups.add_policy(group2['uuid'], policy['uuid'])

        assert_that(
            self.client.policies.get(policy['uuid'])['acl'],
            contains_inanyorder('service1.me.#', 'service2.#'),
        )

        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(404, client.policies.get, policy['uuid'])

            policy_in_subtenant = client.policies.new(name='in sub-tenant')
            assert_that(
                self.client.policies.get(policy_in_subtenant['uuid']),
                has_entries(uuid=uuid_(), name='in sub-tenant'),
            )

    @fixtures.http.policy(name='foobar', shared=True)
    def test_get_when_shared(self, policy):
        response = self.client.policies.get(policy['uuid'])
        assert_that(
            response,
            has_entries(
                name='foobar',
                read_only=False,
                shared=True,
                tenant_uuid=policy['tenant_uuid'],
            ),
        )

        with self.client_in_subtenant() as (client, _, tenant):
            response = client.policies.get(policy['uuid'])
            assert_that(
                response,
                has_entries(
                    name='foobar',
                    read_only=True,
                    shared=False,
                    tenant_uuid=tenant['uuid'],
                ),
            )
            assert_that(
                response['tenant_uuid'],
                not_(equal_to(policy['tenant_uuid'])),
            )

    @fixtures.http.policy()
    def test_delete(self, policy):
        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(404, client.policies.delete, policy['uuid'])
            policy_in_subtenant = client.policies.new(name='in sub-tenant')
            assert_no_error(self.client.policies.delete, policy_in_subtenant['uuid'])
        assert_http_error(404, self.client.policies.delete, UNKNOWN_UUID)
        assert_no_error(self.client.policies.delete, policy['uuid'])
        assert_http_error(404, self.client.policies.delete, policy['uuid'])

    def test_delete_default_policy(self):
        policy = self.client.policies.list(slug=ALL_USERS_POLICY_SLUG)['items'][0]
        assert_http_error(403, self.client.policies.delete, policy['uuid'])

    @fixtures.http.policy(slug='top', shared=True)
    def test_delete_when_shared_and_read_only(self, policy):
        with self.client_in_subtenant() as (client, _, tenant):
            assert_http_error(403, client.policies.delete, policy['uuid'])
        assert_no_error(self.client.policies.delete, policy['uuid'])

    @fixtures.http.policy(
        name='foobar',
        description='a test policy',
        acl=['dird.me.#', 'ctid-ng.#'],
    )
    def test_put(self, policy):
        assert_http_error(404, self.client.policies.edit, UNKNOWN_UUID, 'foobaz')

        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(404, client.policies.edit, policy['uuid'], 'foobaz')

            policy_in_subtenant = client.policies.new(name='in sub-tenant')
            assert_that(
                self.client.policies.edit(policy_in_subtenant['uuid'], 'foobaz'),
                has_entries(uuid=policy_in_subtenant['uuid'], name='foobaz'),
            )

        response = self.client.policies.edit(policy['uuid'], 'foobaz')
        assert_that(
            response,
            has_entries(
                uuid=equal_to(policy['uuid']),
                name=equal_to('foobaz'),
                slug=equal_to('foobar'),
                description=none(),
                acl=empty(),
            ),
        )

    @fixtures.http.policy(slug='ABC')
    def test_put_slug_is_read_only(self, policy):
        new_body = dict(policy)
        new_body['slug'] = 'DEF'

        result = self.client.policies.edit(policy['uuid'], **new_body)

        assert_that(result, has_entries(**policy))

    def test_put_default_policy(self):
        policy = self.client.policies.list(slug=ALL_USERS_POLICY_SLUG)['items'][0]
        assert_http_error(403, self.client.policies.edit, policy['uuid'], 'name')

    @fixtures.http.policy(shared=True)
    def test_put_when_shared(self, policy):
        with self.client_in_subtenant() as (client, _, tenant):
            assert_http_error(403, client.policies.edit, policy['uuid'], 'name')
        assert_no_error(self.client.policies.edit, policy['uuid'], **policy)

    @fixtures.http.user(username='foo', password='bar')
    @fixtures.http.policy()
    def test_put_when_policy_has_more_access_than_token(self, user, policy):
        user_client = self.make_auth_client('foo', 'bar')
        acl = ['auth.#', 'authorized', '!unauthorized']
        user_policy = self.client.policies.new(name='foo-policy', acl=acl)
        self.client.users.add_policy(user['uuid'], user_policy['uuid'])
        token = user_client.token.new(expiration=30)['token']
        user_client.set_token(token)

        new_body = dict(policy)
        new_body['acl'] = ['authorized', 'unauthorized']
        assert_http_error(401, user_client.policies.edit, policy['uuid'], **new_body)

        new_body['acl'] = ['authorized', '!forbid-access']
        user_client.policies.edit(policy['uuid'], **new_body)

        policy = user_client.policies.get(policy['uuid'])
        assert_that(policy, has_entries(acl=new_body['acl']))

        self.client.policies.delete(user_policy['uuid'])

    @fixtures.http.policy(acl=['dird.me.#', 'ctid-ng.#'])
    def test_add_access(self, policy):
        assert_http_error(404, self.client.policies.add_access, UNKNOWN_UUID, '#')
        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(404, client.policies.add_access, policy['uuid'], '#')

            policy_in_subtenant = client.policies.new(name='in sub-tenant')
            self.client.policies.add_access(policy_in_subtenant['uuid'], '#')
            assert_that(
                client.policies.get(policy_in_subtenant['uuid']),
                has_entries(uuid=policy_in_subtenant['uuid'], acl=contains('#')),
            )

        self.client.policies.add_access(policy['uuid'], 'new.access.#')

        expected_acl = ['dird.me.#', 'ctid-ng.#'] + ['new.access.#']
        response = self.client.policies.get(policy['uuid'])
        assert_that(
            response,
            has_entries(
                uuid=policy['uuid'],
                acl=contains_inanyorder(*expected_acl),
            ),
        )

    @fixtures.http.user(username='foo', password='bar')
    @fixtures.http.policy()
    def test_add_access_when_policy_has_more_access_than_token(self, user, policy):
        user_client = self.make_auth_client('foo', 'bar')
        acl = ['auth.#', 'authorized', '!unauthorized']
        user_policy = self.client.policies.new(name='foo-policy', acl=acl)
        self.client.users.add_policy(user['uuid'], user_policy['uuid'])
        token = user_client.token.new(expiration=30)['token']
        user_client.set_token(token)

        assert_http_error(
            401,
            user_client.policies.add_access,
            policy['uuid'],
            'unauthorized',
        )

        user_client.policies.add_access(policy['uuid'], 'authorized')
        user_client.policies.add_access(policy['uuid'], '!forbid-access')

        policy = user_client.policies.get(policy['uuid'])
        assert_that(policy, has_entries(acl=['authorized', '!forbid-access']))

        self.client.policies.delete(user_policy['uuid'])

    @fixtures.http.policy(acl=['dird.me.#', 'ctid-ng.#'])
    def test_remove_access(self, policy):
        assert_http_error(404, self.client.policies.remove_access, UNKNOWN_UUID, '#')

        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(404, client.policies.remove_access, policy['uuid'], '#')

            policy_in_subtenant = client.policies.new(name='in sub-tenant', acl=['#'])
            self.client.policies.remove_access(policy_in_subtenant['uuid'], '#')
            assert_that(
                client.policies.get(policy_in_subtenant['uuid']),
                has_entries(uuid=policy_in_subtenant['uuid'], acl=empty()),
            )

        self.client.policies.remove_access(policy['uuid'], 'ctid-ng.#')

        response = self.client.policies.get(policy['uuid'])
        assert_that(response, has_entries(acl=contains_inanyorder('dird.me.#')))


@base.use_asset('base')
class TestPoliciesBySlug(base.APIIntegrationTest):
    @fixtures.http.policy(slug='my_policy')
    def test_get(self, policy):
        response = self.client.policies.get(policy['slug'])
        assert_that(response, has_entries(slug='my_policy'))

        assert_http_error(404, self.client.policies.get, UNKNOWN_SLUG)

    @fixtures.http.policy()
    def test_get_multi_tenant(self, policy):
        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(404, client.policies.get, policy['slug'])

            slug = 'slug_in_sub_tenant'
            client.policies.new(name=slug, slug=slug)

            assert_http_error(404, self.client.policies.get, slug)

            response = client.policies.get(slug)
            assert_that(response, has_entries(slug=slug))

    @fixtures.http.policy()
    def test_delete(self, policy):
        assert_http_error(404, self.client.policies.delete, UNKNOWN_SLUG)
        assert_no_error(self.client.policies.delete, policy['slug'])
        assert_http_error(404, self.client.policies.delete, policy['slug'])

    @fixtures.http.policy()
    def test_delete_multi_tenant(self, policy):
        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(404, client.policies.delete, policy['slug'])

            slug = 'slug_in_sub_tenant'
            client.policies.new(name=slug, slug=slug)

            assert_http_error(404, self.client.policies.get, slug)

            assert_no_error(client.policies.delete, slug)

    @fixtures.http.policy(name='name')
    def test_put(self, policy):
        new_name = 'other-name'
        assert_http_error(404, self.client.policies.edit, UNKNOWN_SLUG, new_name)

        response = self.client.policies.edit(policy['slug'], new_name)
        assert_that(response, has_entries(name=new_name, slug=policy['slug']))

    @fixtures.http.policy(name='name')
    def test_put_multi_tenant(self, policy):
        new_name = 'other-name'
        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(404, client.policies.edit, policy['slug'], new_name)

            slug = 'slug_in_sub_tenant'
            client.policies.new(name=slug, slug=slug)

            assert_http_error(404, self.client.policies.edit, slug, new_name)

            response = client.policies.edit(slug, new_name)
            assert_that(response, has_entries(slug=slug, name=new_name))

    @fixtures.http.policy(acl=['service1', 'service2'])
    def test_add_access(self, policy):
        access = 'service3'
        assert_http_error(404, self.client.policies.add_access, UNKNOWN_SLUG, access)

        self.client.policies.add_access(policy['slug'], access)

        expected_acl = [access, *policy['acl']]
        response = self.client.policies.get(policy['slug'])
        assert_that(response, has_entries(acl=contains_inanyorder(*expected_acl)))

    @fixtures.http.policy()
    def test_add_access_multi_tenant(self, policy):
        access = 'service1'
        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(404, client.policies.add_access, policy['slug'], access)

            slug = 'slug_in_sub_tenant'
            client.policies.new(name=slug, slug=slug, acl=[])

            assert_http_error(404, self.client.policies.add_access, slug, access)

            client.policies.add_access(slug, access)
            response = client.policies.get(slug)
            assert_that(response, has_entries(acl=[access]))

    @fixtures.http.policy(acl=['service1', 'service2'])
    def test_remove_access(self, policy):
        access = 'service1'
        assert_http_error(404, self.client.policies.remove_access, UNKNOWN_SLUG, access)

        self.client.policies.remove_access(policy['slug'], access)

        response = self.client.policies.get(policy['slug'])
        assert_that(response, has_entries(acl=['service2']))

    @fixtures.http.policy(acl=['service1', 'service2'])
    def test_remove_access_multi_tenant(self, policy):
        access = 'service1'
        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(
                404,
                client.policies.remove_access,
                policy['slug'],
                access,
            )

            slug = 'slug_in_sub_tenant'
            client.policies.new(name=slug, slug=slug, acl=['service1', 'service2'])

            assert_http_error(404, self.client.policies.remove_access, slug, access)

            client.policies.remove_access(slug, access)
            response = client.policies.get(slug)
            assert_that(response, has_entries(acl=['service2']))
