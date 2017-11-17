# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import requests
from hamcrest import (
    assert_that,
    calling,
    contains,
    contains_inanyorder,
    empty,
    has_entries,
    has_items,
    has_properties,
)
from xivo_auth_client import Client
from xivo_test_helpers.hamcrest.uuid_ import uuid_
from xivo_test_helpers.hamcrest.raises import raises
from .helpers import fixtures
from .helpers.base import (
    assert_http_error,
    assert_no_error,
    MockBackendTestCase,
)

UNKNOWN_UUID = '00000000-0000-0000-0000-000000000000'


class TestUsers(MockBackendTestCase):

    def tearDown(self):
        for user in self.client.users.list()['items']:
            self.client.users.delete(user['uuid'])

    @fixtures.http_user()
    def test_delete(self, user):
        assert_http_error(404, self.client.users.delete, UNKNOWN_UUID)
        assert_no_error(self.client.users.delete, user['uuid'])
        assert_http_error(404, self.client.users.delete, user['uuid'])

    def test_post(self):
        username, email, password = 'foobar', 'foobar@example.com', 's3cr37'
        user = self.client.users.new(username=username, email_address=email, password=password)

        assert_that(
            user,
            has_entries(
                'uuid', uuid_(),
                'username', username,
                'emails', contains_inanyorder(
                    has_entries(
                        'address', 'foobar@example.com',
                        'main', True,
                        'confirmed', False,
                    ),
                ),
            ),
        )

    def test_list(self):
        foo = ('foo', 'foo@example.com', 's3cr37')
        bar = ('bar', 'bar@example.com', '$$bar$$')
        baz = ('baz', 'baz@example.com', '5fb9359e-4135-4a0b-aaed-97ae6a0b140d')

        for username, email, password in (foo, bar, baz):
            self.client.users.new(username=username, email_address=email, password=password)

        assert_that(
            self.client.users.list(search='ba'),
            has_entries(
                'total', 3,
                'filtered', 2,
                'items', contains_inanyorder(
                    has_entries('username', 'bar'),
                    has_entries('username', 'baz'),
                ),
            ),
        )

        assert_that(
            self.client.users.list(username='baz'),
            has_entries(
                'total', 3,
                'filtered', 1,
                'items', contains_inanyorder(
                    has_entries('username', 'baz'),
                ),
            ),
        )

        assert_that(
            self.client.users.list(order='username', direction='desc'),
            has_entries(
                'total', 3,
                'filtered', 3,
                'items', contains(
                    has_entries('username', 'foo'),
                    has_entries('username', 'baz'),
                    has_entries('username', 'bar'),
                ),
            ),
        )

        assert_that(
            self.client.users.list(limit=1, offset=1, order='username', direction='asc'),
            has_entries(
                'total', 3,
                'filtered', 3,
                'items', contains(
                    has_entries('username', 'baz'),
                ),
            ),
        )

    def test_get(self):
        username, email, password = 'foobar', 'foobar@example.com', 's3cr37'
        user = self.client.users.new(username=username, email_address=email, password=password)

        result = self.client.users.get(user['uuid'])
        assert_that(
            result,
            has_entries(
                'uuid', uuid_(),
                'username', username,
                'emails', contains_inanyorder(
                    has_entries(
                        'address', email,
                        'confirmed', False,
                        'main', True,
                    ),
                ),
            ),
        )

    @fixtures.http_user(username='foo', password='bar')
    @fixtures.http_policy(name='two', acl_templates=['acl.one.{{ username }}', 'acl.two'])
    @fixtures.http_policy(name='one', acl_templates=['this.is.a.test.acl'])
    def test_user_policy(self, policy_1, policy_2, user):
        result = self.client.users.get_policies(user['uuid'])
        assert_that(
            result,
            has_entries(
                'total', 0,
                'items', empty(),
                'filtered', 0,
            ),
            'not associated',
        )

        self.client.users.add_policy(user['uuid'], policy_1['uuid'])
        self.client.users.add_policy(user['uuid'], policy_2['uuid'])

        user_client = Client(
            self.get_host(), port=self.service_port(9497, 'auth'), verify_certificate=False,
            username='foo', password='bar')
        token_data = user_client.token.new('wazo_user', expiration=5)
        assert_that(
            token_data,
            has_entries(
                'acls', has_items(
                    'acl.one.foo',
                    'this.is.a.test.acl',
                    'acl.two',
                ),
            ),
            'generated acl',
        )

        self.client.users.remove_policy(user['uuid'], policy_2['uuid'])

        assert_that(
            calling(
                self.client.users.add_policy
            ).with_args('8ee4e6a3-533e-4b00-99b2-33b2e55102f2', policy_2['uuid']),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 404)),
            ),
            'unknown user',
        )

        assert_that(
            calling(
                self.client.users.add_policy
            ).with_args(user['uuid'], '113bb403-7914-4685-a0ec-330676e61f7c'),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 404)),
            ),
            'unknown policy',
        )

        result = self.client.users.get_policies(user['uuid'])
        assert_that(
            result,
            has_entries(
                'total', 1,
                'items', contains(has_entries('name', 'one')),
                'filtered', 1,
            ),
            'not associated',
        )

        result = self.client.users.get_policies(user['uuid'], search='two')
        assert_that(
            result,
            has_entries(
                'total', 1,
                'items', empty(),
                'filtered', 0,
            ),
            'not associated',
        )

        self.client.users.remove_policy(user['uuid'], policy_1['uuid'])

        assert_that(
            calling(
                self.client.users.remove_policy
            ).with_args(user['uuid'], policy_1['uuid']),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 404)),
            ),
            'no association found',
        )
