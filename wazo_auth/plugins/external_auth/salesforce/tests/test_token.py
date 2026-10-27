# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest import TestCase

from hamcrest import assert_that, equal_to, has_entries, is_

from ..token import is_expired, new_link, refreshed_link

NOW = 1_800_000_000
LIFETIME = 7200


class TestNewLink(TestCase):
    def test_no_expires_in_expires_after_the_configured_lifetime(self):
        link = new_link({'access_token': 'a', 'refresh_token': 'r'}, LIFETIME, NOW)

        assert_that(link['token_expiration'], equal_to(NOW + LIFETIME))

    def test_expires_in_wins_over_the_configured_lifetime(self):
        link = new_link({'access_token': 'a', 'expires_in': 900}, LIFETIME, NOW)

        assert_that(link['token_expiration'], equal_to(NOW + 900))

    def test_expires_in_sent_as_text_is_a_number_of_seconds(self):
        # oauthlib checks int(expires_in) but leaves the text in the token
        link = new_link({'access_token': 'a', 'expires_in': '900'}, LIFETIME, NOW)

        assert_that(link['token_expiration'], equal_to(NOW + 900))

    def test_keeps_the_fields_a_caller_needs(self):
        token_data = {
            'access_token': 'a',
            'refresh_token': 'r',
            'instance_url': 'https://example.my.salesforce.com',
            'scope': ['api', 'refresh_token', 'id'],
            'id': 'https://login.example.com/id/00D/005',
            'signature': 'sig',
        }

        link = new_link(token_data, LIFETIME, NOW)

        assert_that(
            link,
            equal_to(
                {
                    'access_token': 'a',
                    'refresh_token': 'r',
                    'token_expiration': NOW + LIFETIME,
                    'scope': 'api refresh_token id',
                    'instance_url': 'https://example.my.salesforce.com',
                }
            ),
        )

    def test_missing_optional_fields_are_null(self):
        link = new_link({'access_token': 'a'}, LIFETIME, NOW)

        assert_that(
            link,
            has_entries(refresh_token=None, scope=None, instance_url=None),
        )


class TestRefreshedLink(TestCase):
    stored = {
        'access_token': 'old',
        'refresh_token': 'stored-refresh',
        'token_expiration': NOW - 10,
        'scope': 'api refresh_token id',
        'instance_url': 'https://old.my.salesforce.com',
    }

    def test_keeps_the_stored_refresh_token_when_none_comes_back(self):
        link = refreshed_link(self.stored, {'access_token': 'new'}, LIFETIME, NOW)

        assert_that(
            link,
            has_entries(
                access_token='new',
                refresh_token='stored-refresh',
                token_expiration=NOW + LIFETIME,
                scope='api refresh_token id',
                instance_url='https://old.my.salesforce.com',
            ),
        )

    def test_takes_a_rotated_refresh_token(self):
        token_data = {'access_token': 'new', 'refresh_token': 'rotated'}

        link = refreshed_link(self.stored, token_data, LIFETIME, NOW)

        assert_that(link['refresh_token'], equal_to('rotated'))

    def test_takes_the_new_instance_url_and_scope(self):
        token_data = {
            'access_token': 'new',
            'instance_url': 'https://new.my.salesforce.com',
            'scope': ['api'],
            'expires_in': 60,
        }

        link = refreshed_link(self.stored, token_data, LIFETIME, NOW)

        assert_that(
            link,
            has_entries(
                instance_url='https://new.my.salesforce.com',
                scope='api',
                token_expiration=NOW + 60,
            ),
        )

    def test_does_not_change_the_stored_link(self):
        refreshed_link(self.stored, {'access_token': 'new'}, LIFETIME, NOW)

        assert_that(self.stored['access_token'], equal_to('old'))


class TestIsExpired(TestCase):
    def test_no_expiration_is_expired(self):
        assert_that(is_expired(None, NOW), is_(True))

    def test_expired_thirty_seconds_ahead(self):
        assert_that(is_expired(NOW + 29, NOW), is_(True))
        assert_that(is_expired(NOW + 31, NOW), is_(False))
