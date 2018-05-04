# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    empty,
    equal_to,
    has_entries,
    none,
)
from xivo_test_helpers.hamcrest.uuid_ import uuid_
from .helpers.base import (
    assert_no_error,
    assert_http_error,
    WazoAuthTestCase,
)
from .helpers import fixtures

UNKNOWN_UUID = '00000000-0000-0000-0000-000000000000'


class TestPolicies(WazoAuthTestCase):

    wazo_default_admin_policy = has_entries('name', 'wazo_default_admin_policy')
    wazo_default_user_policy = has_entries('name', 'wazo_default_user_policy')
    wazo_default_master_user_policy = has_entries('name', 'wazo_default_master_user_policy')

    @fixtures.http_policy(name='foobaz')
    @fixtures.http_policy(name='foobar', description='a test policy',
                          acl_templates=['dird.me.#', 'ctid-ng.#'])
    def test_post(self, foobar, foobaz):
        assert_that(
            foobar,
            has_entries(
                uuid=uuid_(),
                name='foobar',
                description='a test policy',
                acl_templates=contains_inanyorder('dird.me.#', 'ctid-ng.#'),
            )
        )

        assert_that(
            foobaz,
            has_entries(
                uuid=uuid_(),
                name='foobaz',
                description=none(),
                acl_templates=empty(),
            )
        )

        assert_http_error(400, self.client.policies.new, '')

    @fixtures.http_policy(name='one')
    @fixtures.http_policy(name='two')
    @fixtures.http_policy(name='three')
    def test_list(self, three, two, one):
        response = self.client.policies.list(search='foobar')
        assert_that(response, has_entries({
            'total': equal_to(0),
            'items': empty()}))

        response = self.client.policies.list()
        assert_that(response, has_entries({
            'total': equal_to(6),
            'items': contains_inanyorder(
                one,
                two,
                three,
                self.wazo_default_user_policy,
                self.wazo_default_master_user_policy,
                self.wazo_default_admin_policy)}))

        response = self.client.policies.list(search='one')
        assert_that(response, has_entries({
            'total': equal_to(1),
            'items': contains_inanyorder(one)}))

        response = self.client.policies.list(order='name', direction='asc')
        assert_that(response, has_entries({
            'total': equal_to(6),
            'items': contains(
                one,
                three,
                two,
                self.wazo_default_admin_policy,
                self.wazo_default_master_user_policy,
                self.wazo_default_user_policy)}))

        response = self.client.policies.list(order='name', direction='asc', limit=1)
        assert_that(response, has_entries({
            'total': equal_to(6),
            'items': contains(one)}))

        response = self.client.policies.list(order='name', direction='asc', limit=1, offset=1)
        assert_that(response, has_entries({
            'total': equal_to(6),
            'items': contains(three)}))

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

    @fixtures.http_policy()
    def test_delete(self, policy):
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
