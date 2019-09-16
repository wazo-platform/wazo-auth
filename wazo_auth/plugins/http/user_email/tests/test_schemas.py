# Copyright 2018-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest import TestCase
from hamcrest import (
    assert_that,
    calling,
    contains,
    contains_inanyorder,
    equal_to,
    has_entries,
    has_entry,
    has_key,
    has_property,
)
from marshmallow import ValidationError

from xivo_test_helpers.hamcrest.raises import raises

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

        body = self.user_schema.load(params)
        assert_that(body, equal_to(expected))

    def test_confirmed_field(self):
        params = {'emails': [ONE, TWO, THREE, FOUR]}
        expected = contains_inanyorder(
            equal_to({'address': ONE['address'], 'main': True}),
            equal_to({'address': TWO['address'], 'main': False}),
            equal_to({'address': THREE['address'], 'main': False}),
            equal_to({'address': FOUR['address'], 'main': False}),
        )

        body = self.user_schema.load(params)
        assert_that(body, expected)

    def test_main_field(self):
        params = {'emails': [ONE, FIVE]}
        assert_that(
            calling(self.user_schema.load).with_args(params),
            raises(
                ValidationError,
                has_property(
                    "messages",
                    has_entries(_schema=contains('Only one address should be main')),
                ),
            ),
        )

        params = {'emails': [TWO]}
        assert_that(
            calling(self.user_schema.load).with_args(params),
            raises(
                ValidationError,
                has_property(
                    "messages",
                    has_entries(
                        _schema=contains('At least one address should be main')
                    ),
                ),
            ),
        )

    def test_address_field(self):
        params = {'emails': [ONE, SIX]}
        assert_that(
            calling(self.user_schema.load).with_args(params),
            raises(
                ValidationError,
                has_property(
                    "messages", has_entries("emails", has_entry(1, has_key('address')))
                ),
            ),
        )

        params = {'emails': [ONE, TWO, TWO]}
        assert_that(
            calling(self.user_schema.load).with_args(params),
            raises(
                ValidationError,
                has_property(
                    "messages",
                    has_entries(
                        _schema=contains('The same address can only be used once')
                    ),
                ),
            ),
        )

        params = {}
        assert_that(
            calling(self.user_schema.load).with_args(params),
            raises(ValidationError, has_property("messages", has_key('emails'))),
        )


class TestAdminUserEmailPutSchema(TestCase):
    def setUp(self):
        self.admin_schema = new_email_put_schema('admin')()

    def test_empty_list(self):
        params = {'emails': []}
        expected = []

        body = self.admin_schema.load(params)
        assert_that(body, equal_to(expected))

    def test_confirmed_field(self):
        params = {'emails': [ONE, TWO, THREE, FOUR]}
        expected = contains_inanyorder(
            has_entries(address=ONE['address'], confirmed=None),
            has_entries(address=TWO['address'], confirmed=None),
            has_entries(address=THREE['address'], confirmed=True),
            has_entries(address=FOUR['address'], confirmed=False),
        )

        body = self.admin_schema.load(params)
        assert_that(body, expected)

    def test_main_field(self):
        params = {'emails': [ONE, FIVE]}
        assert_that(
            calling(self.admin_schema.load).with_args(params),
            raises(
                ValidationError,
                has_property(
                    "messages",
                    has_entries(_schema=contains('Only one address should be main')),
                ),
            ),
        )

        params = {'emails': [TWO]}
        assert_that(
            calling(self.admin_schema.load).with_args(params),
            raises(
                ValidationError,
                has_property(
                    "messages",
                    has_entries(
                        _schema=contains('At least one address should be main')
                    ),
                ),
            ),
        )

    def test_address_field(self):
        params = {'emails': [ONE, SIX]}
        assert_that(
            calling(self.admin_schema.load).with_args(params),
            raises(
                ValidationError,
                has_property(
                    "messages", has_entries("emails", has_entry(1, has_key('address')))
                ),
            ),
        )

        params = {'emails': [ONE, TWO, TWO]}
        assert_that(
            calling(self.admin_schema.load).with_args(params),
            raises(
                ValidationError,
                has_property(
                    "messages",
                    has_entries(
                        _schema=contains('The same address can only be used once')
                    ),
                ),
            ),
        )
