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
from xivo_test_helpers.hamcrest.uuid_ import uuid_
from .helpers.base import (
    assert_no_error,
    assert_http_error,
    assert_sorted,
    SUB_TENANT_UUID,
    WazoAuthTestCase,
)
from .helpers import fixtures
from .helpers.constants import UNKNOWN_UUID, NB_DEFAULT_POLICIES, DEFAULT_POLICY_NAME


class TestPolicies(WazoAuthTestCase):

    wazo_default_admin_policy = has_entries('name', 'wazo_default_admin_policy')
    wazo_default_user_policy = has_entries('name', 'wazo_default_user_policy')
    wazo_default_master_user_policy = has_entries(
        'name', 'wazo_default_master_user_policy'
    )

    @fixtures.http.policy(name='foobaz')
    @fixtures.http.tenant()
    def test_post(self, tenant, foobaz):
        assert_that(
            foobaz,
            has_entries(
                uuid=uuid_(),
                name='foobaz',
                slug='foobaz',
                description=none(),
                acl=empty(),
                tenant_uuid=self.top_tenant_uuid,
            ),
        )

        policy_args = {
            'name': 'foobar',
            'slug': 'slug1',
            'description': 'a test policy',
            'acl': ['dird.me.#', 'ctid-ng.#'],
            'tenant_uuid': tenant['uuid'],
        }
        # Specify the tenant_uuid
        with self.policy(self.client, **policy_args) as policy:
            assert_that(policy, has_entries(uuid=uuid_(), **policy_args))

        # Specify the a tenant uuid in another sub-tenant tree
        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(401, client.policies.new, **policy_args)

        # Invalid body
        assert_http_error(400, self.client.policies.new, '')

        # Deprecated acl_templates key
        policy_args['acl_templates'] = policy_args.pop('acl')
        with self.policy(self.client, **policy_args) as policy:
            assert_that(
                policy,
                has_entries(
                    uuid=uuid_(),
                    acl_templates=policy_args['acl_templates'],
                    acl=policy_args['acl_templates'],
                ),
            )

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

        url = 'http://localhost:{}/0.1/policies'.format(self.service_port(9497, 'auth'))
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

    @fixtures.http.tenant(slug='dup')
    def test_post_duplicate_slug(self, a):
        assert_http_error(409, self.client.policies.new, slug='dup')

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='one', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='two', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='three', tenant_uuid=SUB_TENANT_UUID)
    def test_list_sorting(self, three, two, one, _):
        action = partial(self.client.policies.list, tenant_uuid=SUB_TENANT_UUID)
        autocreated_policy = self.client.policies.list(
            name=DEFAULT_POLICY_NAME,
            tenant_uuid=SUB_TENANT_UUID,
        )['items'][0]
        expected = [one, three, two, autocreated_policy]
        assert_sorted(action, order='name', expected=expected)

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='one', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='two', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='three', tenant_uuid=SUB_TENANT_UUID)
    def test_list_tenant_filtering(self, three, two, one, _):
        # Different tenant
        response = self.client.policies.list(tenant_uuid=self.top_tenant_uuid)
        assert_that(response, has_entries(items=not_(has_items(one, two, three))))

        # Different tenant with recurse
        response = self.client.policies.list(
            recurse=True, tenant_uuid=self.top_tenant_uuid
        )
        assert_that(response, has_entries(items=has_items(one, two, three)))

        # Same tenant
        response = self.client.policies.list(tenant_uuid=SUB_TENANT_UUID)
        assert_that(
            response,
            has_entries(
                total=3 + NB_DEFAULT_POLICIES,
                items=has_items(one, two, three),
            ),
        )

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='one', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='two', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='three', tenant_uuid=SUB_TENANT_UUID)
    def test_list_searching(self, three, two, one, _):
        response = self.client.policies.list(tenant_uuid=SUB_TENANT_UUID, search='one')
        assert_that(response, has_entries(total=1, items=contains(one)))

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='one', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='two', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='three', tenant_uuid=SUB_TENANT_UUID)
    def test_list_paginating(self, three, two, one, _):
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

    @fixtures.http.policy(
        name='foobar',
        description='a test policy',
        acl=['dird.me.#', 'ctid-ng.#'],
    )
    @fixtures.http.user()
    @fixtures.http.user()
    @fixtures.http.group()
    @fixtures.http.group()
    def test_get(self, group1, group2, user1, user2, policy):
        response = self.client.policies.get(policy['uuid'])
        assert_that(
            response,
            has_entries(
                name='foobar',
                description='a test policy',
                acl=contains_inanyorder('dird.me.#', 'ctid-ng.#'),
            ),
        )

        assert_http_error(404, self.client.policies.get, UNKNOWN_UUID)

        self.client.users.add_policy(user1['uuid'], policy['uuid'])
        self.client.users.add_policy(user2['uuid'], policy['uuid'])
        self.client.groups.add_policy(group1['uuid'], policy['uuid'])
        self.client.groups.add_policy(group2['uuid'], policy['uuid'])

        assert_that(
            self.client.policies.get(policy['uuid'])['acl'],
            contains_inanyorder('dird.me.#', 'ctid-ng.#'),
        )

        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(404, client.policies.get, policy['uuid'])

            policy_in_subtenant = client.policies.new(name='in sub-tenant')
            assert_that(
                self.client.policies.get(policy_in_subtenant['uuid']),
                has_entries(uuid=uuid_(), name='in sub-tenant'),
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
