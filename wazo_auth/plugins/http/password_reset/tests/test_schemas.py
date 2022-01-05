# Copyright 2018-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from hamcrest import (
    assert_that,
    calling,
    contains,
    equal_to,
    has_entries,
    has_property,
    not_,
)

from marshmallow import ValidationError
from wazo_test_helpers.hamcrest.raises import raises

from ..schemas import PasswordResetQueryParameters


class TestSchema(unittest.TestCase):
    def setUp(self):
        self.password_query_parameters_schema = PasswordResetQueryParameters()

    def test_the_email_field(self):
        email = 'foobar@example.com'
        query_string = {'email': email}

        result = self.password_query_parameters_schema.load(query_string)

        assert_that(result, has_entries(email_address=email))

    def test_that_username_and_email_are_mutually_exclusive(self):
        query_string = {'email': 'foo@bar.com', 'username': 'foobar'}

        assert_that(
            calling(self.password_query_parameters_schema.load).with_args(query_string),
            raises(
                ValidationError,
                has_property(
                    "messages",
                    has_entries(
                        _schema=contains('"username" or "email" should be used')
                    ),
                ),
            ),
        )

    def test_username_only(self):
        query_string = {'username': 'foobar'}

        result = self.password_query_parameters_schema.load(query_string)

        assert_that(result, has_entries(username='foobar', email_address=None))

    def test_email_only(self):
        query_string = {'email': 'foobar@example.com'}

        result = self.password_query_parameters_schema.load(query_string)

        assert_that(
            result, has_entries(username=None, email_address='foobar@example.com')
        )

    def test_invalid_field(self):
        query_string = {'username': 300 * 'a'}
        assert_that(
            calling(self.password_query_parameters_schema.load).with_args(query_string),
            raises(ValidationError, has_property("messages", not_(equal_to(None)))),
        )

        query_string = {'email': 'patate'}
        assert_that(
            calling(self.password_query_parameters_schema.load).with_args(query_string),
            raises(ValidationError, has_property("messages", not_(equal_to(None)))),
        )
