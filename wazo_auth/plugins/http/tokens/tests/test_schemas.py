# Copyright 2019-2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime, timezone
from unittest import TestCase

from hamcrest import assert_that, calling, has_entry, has_key, has_properties, not_
from marshmallow.exceptions import ValidationError
from wazo_test_helpers.hamcrest.raises import raises

from ..schemas import RefreshTokenListSchema, RefreshTokenSchema, TokenRequestSchema


class TestTokenRequestSchema(TestCase):
    def setUp(self):
        self.schema = TokenRequestSchema()

    def test_invalid_expiration(self):
        invalid_values = [None, True, False, 'foobar', 0]

        for value in invalid_values:
            body = {'expiration': value}
            assert_that(
                calling(self.schema.load).with_args(body),
                raises(ValidationError).matching(
                    has_properties(messages=has_key('expiration'))
                ),
            )

    def test_minimal_body(self):
        body = {}
        assert_that(calling(self.schema.load).with_args(body), not_(raises(Exception)))

    def test_that_acces_type_offline_requires_a_client_id(self):
        body = {'access_type': 'offline'}

        assert_that(
            calling(self.schema.load).with_args(body),
            raises(ValidationError).matching(has_properties(field_name='_schema')),
        )

    def test_that_the_access_type_is_online_when_using_a_refresh_token(self):
        body = {'refresh_token': 'foobar', 'client_id': 'x'}

        assert_that(calling(self.schema.load).with_args(body), not_(raises(Exception)))

        assert_that(
            calling(self.schema.load).with_args({'access_type': 'online', **body}),
            not_(raises(Exception)),
        )

        assert_that(
            calling(self.schema.load).with_args({'access_type': 'offline', **body}),
            raises(ValidationError).matching(has_properties(field_name='_schema')),
        )

    def test_that_a_refresh_token_requires_a_client_id(self):
        body = {'refresh_token': 'the-token'}

        assert_that(
            calling(self.schema.load).with_args({'client_id': 'x', **body}),
            not_(raises(Exception)),
        )

        assert_that(
            calling(self.schema.load).with_args(body),
            raises(ValidationError).matching(has_properties(field_name='_schema')),
        )

    def test_that_using_both_tenant_id_and_domain_name_raises_400(self):
        body = {'tenant_id': 'x', 'domain_name': 'wazo.io'}

        assert_that(
            calling(self.schema.load).with_args(body),
            raises(ValidationError).matching(has_properties(field_name='_schema')),
        )


class TestRefreshTokenSchema(TestCase):
    def setUp(self):
        self.schema = RefreshTokenSchema()
        # as returned by RefreshTokenDAO.list_()
        self.refresh_token = {
            'uuid': 'the-secret-refresh-token',
            'user_uuid': 'a014e8f7-f305-492a-9350-51f149ca8f27',
            'tenant_uuid': '007ca8d5-d361-42de-a0ed-8680105596b0',
            'client_id': 'wazo-shift-android',
            'mobile': True,
            'created_at': datetime(2026, 9, 10, 15, 8, 9, tzinfo=timezone.utc),
            'user_agent': 'wazo-shift/2.4.1 (Android 14)',
            'remote_addr': '203.0.113.7',
            'metadata': {},
        }

    def test_that_the_user_agent_is_exposed(self):
        result = self.schema.dump(self.refresh_token)

        assert_that(result, has_entry('user_agent', 'wazo-shift/2.4.1 (Android 14)'))

    def test_that_the_remote_addr_is_not_exposed(self):
        result = self.schema.dump(self.refresh_token)

        assert_that(result, not_(has_key('remote_addr')))

    def test_that_the_refresh_token_secret_is_not_exposed(self):
        # auth_refresh_token.uuid is the bearer secret handed to the client
        result = self.schema.dump(self.refresh_token)

        assert_that(result, not_(has_key('uuid')))


class TestRefreshTokenListSchema(TestCase):
    def setUp(self):
        self.schema = RefreshTokenListSchema()

    def test_that_the_user_agent_is_searchable(self):
        result = self.schema.load({'user_agent': 'wazo-shift/2.4.1 (Android 14)'})

        assert_that(result, has_entry('user_agent', 'wazo-shift/2.4.1 (Android 14)'))

    def test_that_the_list_can_be_sorted_by_client_id(self):
        result = self.schema.load({'order': 'client_id'})

        assert_that(result, has_entry('order', 'client_id'))
