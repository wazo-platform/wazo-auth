# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from uuid import UUID

from hamcrest import assert_that, equal_to, has_entries

from wazo_auth import config, exceptions
from wazo_auth.tests.test_http import HTTPAppTestCase

USER_UUID = UUID('951d7c53-1801-4835-aacf-3352e72a5cd9')
EMAIL_UUID = UUID('9dd5d9f0-a5e8-44f1-b77c-4190df04db5c')
UNKNOWN_UUID = UUID('00000000-0000-0000-0000-000000000000')
USERNAME = 'foobar'
EMAIL_ADDRESS = 'foobar@example.com'


class TestUserEmailConfirmResource(HTTPAppTestCase):
    def setUp(self):
        super().setUp(config._DEFAULT_CONFIG)
        self.url = '/0.1/users/{}/emails/{}/confirm'

    def test_unknown_user(self):
        self.user_service.get_user.side_effect = exceptions.UnknownUserException(
            UNKNOWN_UUID
        )

        url = self.url.format(UNKNOWN_UUID, EMAIL_UUID)
        result = self.app.get(url)

        assert_that(result.status_code, equal_to(404))
        assert_that(
            result.json,
            has_entries(resource='users', details=has_entries(uuid=str(UNKNOWN_UUID))),
        )

    def test_unknown_email(self):
        user_data = {
            'username': USERNAME,
            'emails': [
                {
                    'uuid': str(EMAIL_UUID),
                    'address': EMAIL_ADDRESS,
                    'confirmed': False,
                    'main': True,
                }
            ],
        }
        self.user_service.get_user.return_value = user_data

        url = self.url.format(USER_UUID, UNKNOWN_UUID)
        result = self.app.get(url)

        assert_that(result.status_code, equal_to(404))
        assert_that(
            result.json,
            has_entries(resource='emails', details=has_entries(uuid=str(UNKNOWN_UUID))),
        )

    def test_already_confirmed_email(self):
        user_data = {
            'username': USERNAME,
            'emails': [
                {
                    'uuid': str(EMAIL_UUID),
                    'address': EMAIL_ADDRESS,
                    'confirmed': True,
                    'main': True,
                }
            ],
        }
        self.user_service.get_user.return_value = user_data

        url = self.url.format(USER_UUID, EMAIL_UUID)
        result = self.app.get(url)

        assert_that(result.status_code, equal_to(409))
        assert_that(
            result.json,
            has_entries(resource='emails', details=has_entries(uuid=str(EMAIL_UUID))),
        )

    def test_get(self):
        user_data = {
            'username': USERNAME,
            'emails': [
                {
                    'uuid': str(EMAIL_UUID),
                    'address': EMAIL_ADDRESS,
                    'confirmed': False,
                    'main': True,
                }
            ],
        }
        self.user_service.get_user.return_value = user_data

        url = self.url.format(USER_UUID, EMAIL_UUID)
        result = self.app.get(url)

        expected_args = (
            USERNAME,
            str(EMAIL_UUID),
            EMAIL_ADDRESS,
            {'hostname': 'localhost'},
        )
        self.email_service.send_confirmation_email.assert_called_once_with(
            *expected_args
        )
        assert_that(result.status_code, equal_to(204))
