# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest import TestCase

from hamcrest import assert_that, has_entries

from ..schemas import UserPostSchema, UserPutSchema


class TestUserSchema(TestCase):
    def setUp(self):
        self.put_schema = UserPutSchema()
        self.post_schema = UserPostSchema()

    def test_authentication_method(self):
        payload = {
            'username': 'foobar',
            'firstname': 'foo',
            'lastname': 'bar',
            'enabled': True,
        }

        user_payload = dict(purpose='user', **payload)
        result = self.put_schema.load(user_payload)
        assert_that(
            result,
            has_entries(
                authentication_method='default',
            ),
        )
        result = self.post_schema.load(user_payload)
        assert_that(
            result,
            has_entries(
                authentication_method='default',
            ),
        )

        internal_payload = dict(purpose='internal', **payload)
        result = self.put_schema.load(internal_payload)
        assert_that(
            result,
            has_entries(
                authentication_method='native',
            ),
        )
        result = self.post_schema.load(internal_payload)
        assert_that(
            result,
            has_entries(
                authentication_method='native',
            ),
        )

        external_api_payload = dict(purpose='external_api', **payload)
        result = self.put_schema.load(external_api_payload)
        assert_that(
            result,
            has_entries(
                authentication_method='native',
            ),
        )
        result = self.post_schema.load(external_api_payload)
        assert_that(
            result,
            has_entries(
                authentication_method='native',
            ),
        )

        user_defined_payload = dict(
            authentication_method='saml', purpose='user', **payload
        )
        result = self.put_schema.load(user_defined_payload)
        assert_that(
            result,
            has_entries(
                authentication_method='saml',
            ),
        )
        result = self.post_schema.load(user_defined_payload)
        assert_that(
            result,
            has_entries(
                authentication_method='saml',
            ),
        )
