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
from hamcrest import assert_that, equal_to, has_entries
from mock import ANY
from wazo_auth.config import _DEFAULT_CONFIG
from wazo_auth.tests.test_http import HTTPAppTestCase


class TestTenantPost(HTTPAppTestCase):

    url = '/0.1/tenants'

    def setUp(self):
        config = dict(_DEFAULT_CONFIG)
        config['enabled_http_plugins']['tenants'] = True
        super(TestTenantPost, self).setUp(config)

    def test_invalid_posts(self):
        invalid_datas = [
            None,
            {'not_name': 'foobar'},
            {'name': ''},
            {'name': 42},
            {'name': 100 * 'foobar'},
        ]

        for invalid_data in invalid_datas:
            result = self.post(invalid_data)
            assert_that(result.status_code, equal_to(400), invalid_data)
            assert_that(
                json.loads(result.data),
                has_entries(
                    'error_id', 'invalid_data',
                    'message', ANY,
                    'resource', 'tenants',
                    'details', has_entries(
                        'name', has_entries(
                            'constraint_id', ANY,
                            'constraint', ANY,
                            'message', ANY,
                        ),
                    ),
                ),
                invalid_data
            )

    def test_that_validated_args_are_passed_to_the_service(self):
        body = {'name': 'foobar', 'ignored': True}
        self.tenant_service.new_tenant.return_value = {
            'name': 'foobar',
            'uuid': '022035fe-f5e5-4c16-bd5f-8fea8f4c9d08',
        }

        result = self.post(body)

        assert_that(result.status_code, equal_to(200))
        assert_that(json.loads(result.data), equal_to(self.tenant_service.new_tenant.return_value))
        self.tenant_service.new_tenant.assert_called_once_with(name='foobar')

    def post(self, data):
        return self.app.post(self.url, data=json.dumps(data), headers=self.headers)
