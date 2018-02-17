# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from unittest import TestCase
from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    equal_to,
    has_entries,
)

from ..schemas import AdminUserEmailPutSchema

ONE = dict(address='one@example.com', main=True)
TWO = dict(address='two@example.com', main=False, confirmed=None)
THREE = dict(address='three@example.com', main=False, confirmed=True)
FOUR = dict(address='four@example.com', main=False, confirmed=False)
FIVE = dict(address='five@example.com', main=True, confirmed=False)
SIX = dict(address='six', main=False, confirmed=False)


class TestAdminUserEmailPutSchema(TestCase):

    def setUp(self):
        self.schema = AdminUserEmailPutSchema()

    def test_empty_list(self):
        params = dict(
            emails=[],
        )
        expected = []

        body, error = self.schema.load(params)
        assert_that(body, equal_to(expected))

    def test_confirmed_field(self):
        params = dict(emails=[ONE, TWO, THREE, FOUR])
        expected = contains_inanyorder(
            has_entries(address=ONE['address'], confirmed=None),
            has_entries(address=TWO['address'], confirmed=None),
            has_entries(address=THREE['address'], confirmed=True),
            has_entries(address=FOUR['address'], confirmed=False),
        )

        body, error = self.schema.load(params)
        assert_that(body, expected)

    def test_main_field(self):
        params = dict(emails=[ONE, FIVE])
        body, error = self.schema.load(params)
        assert_that(error, has_entries(_schema=contains('Only one address should be main')))

        params = dict(emails=[TWO])
        body, error = self.schema.load(params)
        assert_that(error, has_entries(_schema=contains('At least one address should be main')))

    def test_address_field(self):
        params = dict(emails=[ONE, SIX])
        body, error = self.schema.load(params)
        field = error['emails'][1].keys()[0]
        assert_that(field, equal_to('address'))

        params = dict(emails=[ONE, TWO, TWO])
        body, error = self.schema.load(params)
        assert_that(error, has_entries(_schema=contains('The same address can only be used once')))
