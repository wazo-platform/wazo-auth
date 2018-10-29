# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import json
from hamcrest import assert_that, equal_to, has_entries
from mock import ANY, Mock, patch, sentinel as s
from wazo_auth.config import _DEFAULT_CONFIG
from wazo_auth.tests.test_http import HTTPAppTestCase


class TestTenantPost(HTTPAppTestCase):

    url = '/0.1/tenants'

    def setUp(self):
        config = dict(_DEFAULT_CONFIG)
        config['enabled_http_plugins']['tenants'] = True
        super().setUp(config)

    @patch('wazo_auth.plugins.http.tenants.http.TenantDetector')
    def test_invalid_posts(self, TenantDetector):
        TenantDetector.autodetect.return_value = Mock(uuid=s.tenant_uuid)

        invalid_datas = [
            {'name': 42},
            {'name': 100 * 'foobar'},
        ]

        for invalid_data in invalid_datas:
            result = self.post(invalid_data)
            assert_that(result.status_code, equal_to(400), invalid_data)
            assert_that(
                json.loads(result.data),
                has_entries(
                    'error_id', 'invalid-data',
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

    @patch('wazo_auth.plugins.http.tenants.http.TenantDetector')
    def test_that_validated_args_are_passed_to_the_service(self, TenantDetector):
        TenantDetector.autodetect.return_value = Mock(uuid=s.tenant_uuid)

        body = {'name': 'foobar', 'ignored': True}
        self.tenant_service.new.return_value = {
            'name': 'foobar',
            'uuid': '022035fe-f5e5-4c16-bd5f-8fea8f4c9d08',
        }

        result = self.post(body)

        assert_that(result.status_code, equal_to(200))
        assert_that(json.loads(result.data), equal_to(self.tenant_service.new.return_value))
        self.tenant_service.new.assert_called_once_with(
            uuid=None,
            name='foobar',
            phone=None,
            contact_uuid=None,
            parent_uuid=s.tenant_uuid,
            address=dict(
                line_1=None,
                line_2=None,
                city=None,
                state=None,
                zip_code=None,
                country=None))

    def post(self, data):
        return self.app.post(self.url, data=json.dumps(data), headers=self.headers)
