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

from hamcrest import assert_that, contains, equal_to, has_entries, any_of
from mock import ANY, Mock, sentinel as s
from unittest import TestCase

from ..config import _DEFAULT_CONFIG
from ..http import new_app


class HTTPAppTestCase(TestCase):

    def setUp(self):
        self.user_service = Mock()
        self.policy_service = Mock()
        token_manager = Mock()
        self.app = new_app(
            _DEFAULT_CONFIG,
            s.backends,
            self.policy_service,
            token_manager,
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

    def test_that_null_fields_are_not_valid(self):
        username, password, email_address = 'foobar', 'b3h01D', 'foobar@example.com'
        valid_body = {
            'username': username,
            'password': password,
            'email_address': email_address,
        }

        for field in ['username', 'password', 'email_address']:
            body = dict(valid_body)
            body[field] = None
            data = json.dumps(body)

            result = self.app.post(self.url, data=data, headers=self.headers)

            assert_that(result.status_code, equal_to(400), field)
            assert_that(
                json.loads(result.data),
                has_entries('error_id', 'invalid_data',
                            'resource', 'users',
                            'details', has_entries(field, has_entries('constraint_id', 'not_null'))),
                field,
            )

    def test_user_list(self):
        params = dict(
            direction='desc',
            order='email_address',
            limit=5,
            offset=42,
            search='foo',
            uuid='5941aabb-9e4a-4d2e-9e1e-7f9929354458',
        )
        expected_total, expected_filtered = 100, 1
        expected_result = [
            dict(
                username='foobar',
                email_address='foobar@example.com',
                uuid='5941aabb-9e4a-4d2e-9e1e-7f9929354458',
            ),
        ]
        self.user_service.list_users.return_value = expected_result
        self.user_service.count_users.side_effect = [expected_total, expected_filtered]

        result = self.app.get(self.url, query_string=params, headers=self.headers)

        assert_that(result.status_code, equal_to(200))
        assert_that(
            json.loads(result.data),
            has_entries(
                'total', expected_total,
                'filtered', expected_filtered,
                'items', expected_result,
            )
        )

    def test_user_get(self):
        uuid = '5730c531-5e47-4de6-be60-c3e28de00de4'
        url = '/'.join([self.url, uuid])
        expected_result = dict(
            username='foobar',
            uuid=uuid,
            emails=[
                {'address': 'foobar@example.com', 'confirmed': True, 'main': True},
            ],
        )
        self.user_service.get_user.return_value = expected_result

        result = self.app.get(url, headers=self.headers)

        assert_that(
            json.loads(result.data),
            equal_to(expected_result),
        )

    def test_user_delete(self):
        uuid = '5730c531-5e47-4de6-be60-c3e28de00de4'
        url = '/'.join([self.url, uuid])

        result = self.app.delete(url, headers=self.headers)

        assert_that(result.status_code, equal_to(204))


class TestPolicyResource(HTTPAppTestCase):

    def setUp(self):
        super(TestPolicyResource, self).setUp()
        self.url = '/0.1/policies'
        self.headers = {'content-type': 'application/json'}

    def test_create_policy_valid(self):
        name = 'valid'
        desc = 'A Valid description'
        input_and_expected = [
            (
                {'name': name},
                {'name': name,
                 'description': None,
                 'acl_templates': []}
            ),
            (
                {'name': name, 'description': desc},
                {'name': name,
                 'description': desc,
                 'acl_templates': []}
            )
        ]

        for policy_data, expected in input_and_expected:
            self.app.post(self.url, data=json.dumps(policy_data), headers=self.headers)
            self.policy_service.create.assert_called_once_with(**expected)
            self.policy_service.reset_mock()

    def test_that_invalid_acl_templates_raise_a_manager_exception(self):
        name = 'foobar'
        templates = [
            {'foo': 'bar'},
            42,
            True,
            False,
            None,
            'auth.*',
            [{'foo': 'bar'}],
            [42],
            ['#', False],
            [None],
        ]

        for template in templates:
            data = {'name': name, 'acl_templates': template}
            result = self.app.post(self.url, data=json.dumps(data), headers=self.headers)
            assert_that(result.status_code, equal_to(400))
            assert_that(
                json.loads(result.data),
                has_entries(
                    'reason', contains('Invalid value supplied for field: acl_templates'),
                ),
                template,
            )

    def test_that_invalid_values_raise_a_manager_exception(self):
        names = [
            None,
            True,
            False,
            '',
            42,
        ]

        for name in names:
            data = {'name': name}
            result = self.app.post(self.url, data=json.dumps(data), headers=self.headers)
            assert_that(result.status_code, equal_to(400))
            assert_that(
                json.loads(result.data),
                has_entries(
                    'reason', contains('Invalid value supplied for field: name'),
                ),
                name,
            )

        descriptions = [
            True,
            False,
            42,
        ]
        for desc in descriptions:
            body = {'name': 'name', 'description': desc}
            result = self.app.post(self.url, data=json.dumps(body), headers=self.headers)
            assert_that(result.status_code, equal_to(400))
            assert_that(
                json.loads(result.data),
                has_entries(
                    'reason', contains('Invalid value supplied for field: description'),
                ),
                desc,
            )

        result = self.app.post(self.url, data='null', headers=self.headers)
        assert_that(result.status_code, equal_to(400))
