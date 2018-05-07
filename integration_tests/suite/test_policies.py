# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from functools import partial
from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    empty,
    equal_to,
    has_entries,
    has_items,
    none,
    not_,
)
from xivo_test_helpers.hamcrest.uuid_ import uuid_
from .helpers.base import (
    assert_no_error,
    assert_http_error,
    assert_sorted,
    WazoAuthTestCase,
)
from .helpers import fixtures

UNKNOWN_UUID = '00000000-0000-0000-0000-000000000000'
SUB_TENANT_UUID = '76502c2b-cce5-409c-ab8f-d1fe41141a2d'


class TestPolicies(WazoAuthTestCase):

    wazo_default_admin_policy = has_entries('name', 'wazo_default_admin_policy')
    wazo_default_user_policy = has_entries('name', 'wazo_default_user_policy')
    wazo_default_master_user_policy = has_entries('name', 'wazo_default_master_user_policy')

    @fixtures.http_policy(name='foobaz')
    @fixtures.http_tenant()
    def test_post(self, tenant, foobaz):
        assert_that(
            foobaz,
            has_entries(
                uuid=uuid_(),
                name='foobaz',
                description=none(),
                acl_templates=empty(),
                tenant_uuid=self.top_tenant_uuid,
            )
        )

        policy_args = {
            'name': 'foobar',
            'description': 'a test policy',
            'acl_templates': ['dird.me.#', 'ctid-ng.#'],
            'tenant_uuid': tenant['uuid'],
        }
        # Specify the tenant_uuid
        with self.policy(self.client, **policy_args) as policy:
            assert_that(
                policy,
                has_entries(
                    uuid=uuid_(),
                    **policy_args
                )
            )

        # Specify the a tenant uuid in another sub-tenant tree
        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(401, client.policies.new, **policy_args)

        # Invalid body
        assert_http_error(400, self.client.policies.new, '')

    @fixtures.http_tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='one', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='two', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='three', tenant_uuid=SUB_TENANT_UUID)
    def test_list_sorting(self, three, two, one, _):
        action = partial(self.client.policies.list, tenant_uuid=SUB_TENANT_UUID)
        expected = [one, three, two]
        assert_sorted(action, order='name', expected=expected)

    @fixtures.http_tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='one', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='two', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='three', tenant_uuid=SUB_TENANT_UUID)
    def test_list_tenant_filtering(self, three, two, one, _):
        # Different tenant
        response = self.client.policies.list(tenant_uuid=self.top_tenant_uuid)
        assert_that(response, has_entries(items=not_(has_items(one, two, three))))

        # Different tenant with recurse
        response = self.client.policies.list(recurse=True, tenant_uuid=self.top_tenant_uuid)
        assert_that(response, has_entries(items=has_items(one, two, three)))

        # Same tenant
        response = self.client.policies.list(tenant_uuid=SUB_TENANT_UUID)
        assert_that(response, has_entries(total=3, items=contains_inanyorder(one, two, three)))

    @fixtures.http_tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='one', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='two', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='three', tenant_uuid=SUB_TENANT_UUID)
    def test_list_searching(self, three, two, one, _):
        response = self.client.policies.list(tenant_uuid=SUB_TENANT_UUID, search='one')
        assert_that(response, has_entries(total=1, items=contains(one)))

    @fixtures.http_tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='one', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='two', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http_policy(name='three', tenant_uuid=SUB_TENANT_UUID)
    def test_list_paginating(self, three, two, one, _):
        response = self.client.policies.list(tenant_uuid=SUB_TENANT_UUID, order='name', limit=1)
        assert_that(response, has_entries(total=3, items=contains(one)))

        response = self.client.policies.list(tenant_uuid=SUB_TENANT_UUID, order='name', offset=1)
        assert_that(response, has_entries(total=3, items=contains_inanyorder(two, three)))

    @fixtures.http_policy(name='foobar', description='a test policy',
                          acl_templates=['dird.me.#', 'ctid-ng.#'])
    @fixtures.http_user()
    @fixtures.http_user()
    @fixtures.http_group()
    @fixtures.http_group()
    def test_get(self, group1, group2, user1, user2, policy):
        response = self.client.policies.get(policy['uuid'])
        assert_that(
            response,
            has_entries(
                name='foobar',
                description='a test policy',
                acl_templates=contains_inanyorder(
                    'dird.me.#',
                    'ctid-ng.#',
                ),
            ),
        )

        assert_http_error(404, self.client.policies.get, UNKNOWN_UUID)

        self.client.users.add_policy(user1['uuid'], policy['uuid'])
        self.client.users.add_policy(user2['uuid'], policy['uuid'])
        self.client.groups.add_policy(group1['uuid'], policy['uuid'])
        self.client.groups.add_policy(group2['uuid'], policy['uuid'])

        assert_that(
            self.client.policies.get(policy['uuid'])['acl_templates'],
            contains_inanyorder(
                'dird.me.#',
                'ctid-ng.#',
            ),
        )

        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(404, client.policies.get, policy['uuid'])

    @fixtures.http_policy()
    def test_delete(self, policy):
        with self.client_in_subtenant() as (client, _, __):
            assert_http_error(404, client.policies.delete, policy['uuid'])
            policy_in_subtenant = client.policies.new(name='in sub-tenant')
            assert_no_error(self.client.policies.delete, policy_in_subtenant['uuid'])
        assert_http_error(404, self.client.policies.delete, UNKNOWN_UUID)
        assert_no_error(self.client.policies.delete, policy['uuid'])
        assert_http_error(404, self.client.policies.delete, policy['uuid'])

    @fixtures.http_policy(name='foobar', description='a test policy',
                          acl_templates=['dird.me.#', 'ctid-ng.#'])
    def test_put(self, policy):
        assert_http_error(404, self.client.policies.edit, UNKNOWN_UUID, 'foobaz')

        response = self.client.policies.edit(policy['uuid'], 'foobaz')
        assert_that(response, has_entries({
            'uuid': equal_to(policy['uuid']),
            'name': equal_to('foobaz'),
            'description': none(),
            'acl_templates': empty()}))

    @fixtures.http_policy(acl_templates=['dird.me.#', 'ctid-ng.#'])
    def test_add_acl_template(self, policy):
        assert_http_error(404, self.client.policies.add_acl_template, UNKNOWN_UUID, '#')

        self.client.policies.add_acl_template(policy['uuid'], 'new.acl.template.#')

        expected_acl_templates = ['dird.me.#', 'ctid-ng.#'] + ['new.acl.template.#']
        response = self.client.policies.get(policy['uuid'])
        assert_that(response, has_entries({
            'uuid': equal_to(policy['uuid']),
            'acl_templates': contains_inanyorder(*expected_acl_templates)}))

    @fixtures.http_policy(acl_templates=['dird.me.#', 'ctid-ng.#'])
    def test_remove_acl_template(self, policy):
        assert_http_error(404, self.client.policies.remove_acl_template, UNKNOWN_UUID, '#')

        self.client.policies.remove_acl_template(policy['uuid'], 'ctid-ng.#')

        response = self.client.policies.get(policy['uuid'])
        assert_that(response, has_entries({
            'acl_templates': contains_inanyorder('dird.me.#')}))
