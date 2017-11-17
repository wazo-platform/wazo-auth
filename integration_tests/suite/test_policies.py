# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import uuid
import requests
from hamcrest import (
    assert_that,
    calling,
    contains,
    contains_inanyorder,
    empty,
    equal_to,
    has_entries,
    none,
)
from xivo_test_helpers.hamcrest.raises import raises
from xivo_test_helpers.hamcrest.uuid_ import uuid_
from .helpers.base import (
    assert_no_error,
    assert_http_error,
    MockBackendTestCase,
)
from .helpers import fixtures

UNKNOWN_UUID = '00000000-0000-0000-0000-000000000000'


class TestPolicies(MockBackendTestCase):

    def tearDown(self):
        for policy in self.client.policies.list()['items']:
            self.client.policies.delete(policy['uuid'])

    @fixtures.http_policy(name='foobaz')
    @fixtures.http_policy(name='foobar', description='a test policy',
                          acl_templates=['dird.me.#', 'ctid-ng.#'])
    def test_post(self, foobar, foobaz):
        assert_that(foobar, has_entries({
            'uuid': uuid_(),
            'name': equal_to('foobar'),
            'description': equal_to('a test policy'),
            'acl_templates': contains_inanyorder('dird.me.#', 'ctid-ng.#')}))

        assert_that(foobaz, has_entries({
            'uuid': uuid_(),
            'name': equal_to('foobaz'),
            'description': none(),
            'acl_templates': empty()}))

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
            'total': equal_to(3),
            'items': contains_inanyorder(one, two, three)}))

        response = self.client.policies.list(search='one')
        assert_that(response, has_entries({
            'total': equal_to(1),
            'items': contains_inanyorder(one)}))

        response = self.client.policies.list(order='name', direction='asc')
        assert_that(response, has_entries({
            'total': equal_to(3),
            'items': contains(one, three, two)}))

        response = self.client.policies.list(order='name', direction='asc', limit=1)
        assert_that(response, has_entries({
            'total': equal_to(3),
            'items': contains(one)}))

        response = self.client.policies.list(order='name', direction='asc', limit=1, offset=1)
        assert_that(response, has_entries({
            'total': equal_to(3),
            'items': contains(three)}))

    @fixtures.http_policy(name='foobar', description='a test policy',
                          acl_templates=['dird.me.#', 'ctid-ng.#'])
    def test_get(self, policy):
        response = self.client.policies.get(policy['uuid'])
        assert_that(response, equal_to(policy))

        assert_http_error(404, self.client.policies.get, UNKNOWN_UUID)

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

    def test_add_acl_template(self):
        unknown_uuid = str(uuid.uuid4())
        assert_that(
            calling(self.client.policies.add_acl_template).with_args(unknown_uuid, '#'),
            raises(requests.HTTPError))

        name, description, acl_templates = 'foobar', 'a test policy', ['dird.me.#', 'ctid-ng.#']
        policy = self.client.policies.new(name, description, acl_templates)

        self.client.policies.add_acl_template(policy['uuid'], 'new.acl.template.#')

        expected_acl_templates = acl_templates + ['new.acl.template.#']
        response = self.client.policies.get(policy['uuid'])
        assert_that(response, has_entries({
            'uuid': equal_to(policy['uuid']),
            'name': equal_to(name),
            'description': equal_to(description),
            'acl_templates': contains_inanyorder(*expected_acl_templates)}))

    def test_remove_acl_template(self):
        unknown_uuid = str(uuid.uuid4())
        assert_that(
            calling(self.client.policies.remove_acl_template).with_args(unknown_uuid, 'foo'),
            raises(requests.HTTPError))

        name, description, acl_templates = 'foobar', 'a test policy', ['dird.me.#', 'ctid-ng.#']
        policy = self.client.policies.new(name, description, acl_templates)

        self.client.policies.remove_acl_template(policy['uuid'], 'ctid-ng.#')

        response = self.client.policies.get(policy['uuid'])
        assert_that(response, has_entries({
            'uuid': equal_to(policy['uuid']),
            'name': equal_to(name),
            'description': equal_to(description),
            'acl_templates': contains_inanyorder(*acl_templates[:-1])}))
