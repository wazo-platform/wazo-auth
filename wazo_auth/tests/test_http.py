# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import json

from hamcrest import assert_that, equal_to, has_entries, any_of
from mock import ANY, Mock, sentinel as s
from unittest import TestCase

from ..config import _DEFAULT_CONFIG
from ..http import new_app


class HTTPAppTestCase(TestCase):

    def setUp(self):
        self.user_service = Mock()
        self.app = new_app(
            _DEFAULT_CONFIG,
            s.backends,
            s.policy_manager,
            s.token_manager,
            self.user_service,
        ).test_client()


class TestUserResource(HTTPAppTestCase):

    def setUp(self):
        super(TestUserResource, self).setUp()
        self.url = '/0.1/users'
        self.headers = {'content-type': 'application/json'}

    def test_that_creating_a_user_calls_the_service(self):
        username, password, email_address = 'foobar', 'b3h01D', 'foobar@example.com'
        uuid = '839a34a1-4027-4046-ad22-af086014874e'
        body = {
            'username': username,
            'password': password,
            'email_address': email_address,
        }
        data = json.dumps(body)
        self.user_service.new_user.return_value = dict(
            uuid=uuid,
            username=username,
            email_address=email_address,
        )

        result = self.app.post(self.url, data=data, headers=self.headers)

        assert_that(result.status_code, equal_to(200))
        self.user_service.new_user.assert_called_once_with(**body)
        assert_that(
            json.loads(result.data.decode(encoding='utf-8')),
            has_entries(
                'uuid', uuid,
                'username', username,
                'email_address', email_address,
            ),
        )

    def test_that_ommiting_a_required_fields_returns_400(self):
        username, password, email_address = 'foobar', 'b3h01D', 'foobar@example.com'
        valid_body = {
            'username': username,
            'password': password,
            'email_address': email_address,
        }

        for field in ['username', 'password', 'email_address']:
            body = dict(valid_body)
            del body[field]
            data = json.dumps(body)

            result = self.app.post(self.url, data=data, headers=self.headers)

            assert_that(result.status_code, equal_to(400), field)
            assert_that(
                json.loads(result.data),
                has_entries('error_id', 'invalid_data',
                            'message', 'Missing data for required field.',
                            'resource', 'users',
                            'details', {field: {'constraint_id': 'required',
                                                'constraint': 'required',
                                                'message': ANY}}),
                field,
            )

    def test_that_an_empty_body_returns_400(self):
        result = self.app.post(self.url, data='null', headers=self.headers)

        assert_that(result.status_code, equal_to(400))
        assert_that(
            json.loads(result.data),
            has_entries('error_id', 'invalid_data')
        )

    def test_that_empty_fields_are_not_valid(self):
        username, password, email_address = 'foobar', 'b3h01D', 'foobar@example.com'
        valid_body = {
            'username': username,
            'password': password,
            'email_address': email_address,
        }

        for field in ['username', 'password', 'email_address']:
            body = dict(valid_body)
            body[field] = ''
            data = json.dumps(body)

            result = self.app.post(self.url, data=data, headers=self.headers)

            assert_that(result.status_code, equal_to(400), field)
            assert_that(
                json.loads(result.data),
                has_entries('error_id', 'invalid_data',
                            'resource', 'users',
                            'details', has_entries(field, has_entries('constraint_id', any_of('length', 'email')))),
                field,
            )
