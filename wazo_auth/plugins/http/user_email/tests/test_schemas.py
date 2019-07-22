# Copyright 2018-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest import TestCase
from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    equal_to,
    has_entries,
    has_key,
)

from ..schemas import new_email_put_schema

ONE = {'address': 'one@example.com', 'main': True}
TWO = {'address': 'two@example.com', 'main': False, 'confirmed': None}
THREE = {'address': 'three@example.com', 'main': False, 'confirmed': True}
FOUR = {'address': 'four@example.com', 'main': False, 'confirmed': False}
FIVE = {'address': 'five@example.com', 'main': True, 'confirmed': False}
SIX = {'address': 'six', 'main': False, 'confirmed': False}


class TestUserEmailPutSchema(TestCase):
    def setUp(self):
        self.user_schema = new_email_put_schema('user')()

    def test_empty_list(self):
        params = {'emails': []}
        expected = []

        body, error = self.user_schema.load(params)
        assert_that(body, equal_to(expected))

    def test_confirmed_field(self):
        params = {'emails': [ONE, TWO, THREE, FOUR]}
        expected = contains_inanyorder(
            equal_to({'address': ONE['address'], 'main': True}),
            equal_to({'address': TWO['address'], 'main': False}),
            equal_to({'address': THREE['address'], 'main': False}),
            equal_to({'address': FOUR['address'], 'main': False}),
        )

        body, error = self.user_schema.load(params)
        assert_that(body, expected)

    def test_main_field(self):
        params = {'emails': [ONE, FIVE]}
        body, error = self.user_schema.load(params)
        assert_that(
            error, has_entries(_schema=contains('Only one address should be main'))
        )

        params = {'emails': [TWO]}
        body, error = self.user_schema.load(params)
        assert_that(
            error, has_entries(_schema=contains('At least one address should be main'))
        )

    def test_address_field(self):
        params = {'emails': [ONE, SIX]}
        body, error = self.user_schema.load(params)
        field = list(error['emails'][1].keys())[0]
        assert_that(field, equal_to('address'))

        params = {'emails': [ONE, TWO, TWO]}
        body, error = self.user_schema.load(params)
        assert_that(
            error,
            has_entries(_schema=contains('The same address can only be used once')),
        )

        params = {}
        body, error = self.user_schema.load(params)
        assert_that(error, has_key('emails'))


class TestAdminUserEmailPutSchema(TestCase):
    def setUp(self):
        self.admin_schema = new_email_put_schema('admin')()

    def test_empty_list(self):
        params = {'emails': []}
        expected = []

        body, error = self.admin_schema.load(params)
        assert_that(body, equal_to(expected))

    def test_confirmed_field(self):
        params = {'emails': [ONE, TWO, THREE, FOUR]}
        expected = contains_inanyorder(
            has_entries(address=ONE['address'], confirmed=None),
            has_entries(address=TWO['address'], confirmed=None),
            has_entries(address=THREE['address'], confirmed=True),
            has_entries(address=FOUR['address'], confirmed=False),
        )

        body, error = self.admin_schema.load(params)
        assert_that(body, expected)

    def test_main_field(self):
        params = {'emails': [ONE, FIVE]}
        body, error = self.admin_schema.load(params)
        assert_that(
            error, has_entries(_schema=contains('Only one address should be main'))
        )

        params = {'emails': [TWO]}
        body, error = self.admin_schema.load(params)
        assert_that(
            error, has_entries(_schema=contains('At least one address should be main'))
        )

    def test_address_field(self):
        params = {'emails': [ONE, SIX]}
        body, error = self.admin_schema.load(params)
        field = list(error['emails'][1].keys())[0]
        assert_that(field, equal_to('address'))

        params = {'emails': [ONE, TWO, TWO]}
        body, error = self.admin_schema.load(params)
        assert_that(
            error,
            has_entries(_schema=contains('The same address can only be used once')),
        )
