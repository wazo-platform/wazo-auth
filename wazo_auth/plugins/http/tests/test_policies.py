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

from hamcrest import assert_that, contains, equal_to, has_entries

from wazo_auth.tests import test_http
from wazo_auth.config import _DEFAULT_CONFIG


class TestPolicyResource(test_http.HTTPAppTestCase):

    def setUp(self):
        super(TestPolicyResource, self).setUp(_DEFAULT_CONFIG)
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
