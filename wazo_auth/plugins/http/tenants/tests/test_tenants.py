# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import json
from hamcrest import assert_that, equal_to, has_entries
from mock import ANY, Mock, sentinel as s
from wazo_auth.flask_helpers import Tenant
from wazo_auth.config import _DEFAULT_CONFIG
from wazo_auth.tests.test_http import HTTPAppTestCase


class TestTenantPost(HTTPAppTestCase):

    url = '/0.1/tenants'

    def setUp(self):
        config = dict(_DEFAULT_CONFIG)
        config['enabled_http_plugins']['tenants'] = True
        self.token_manager = Mock()
        self.user_service = Mock()
        self.user_service.list_tenants.return_value = [
            {'uuid': s.tenant_uuid, 'name': s.tenant_name}
        ]
        Tenant.setup(self.token_manager, self.user_service)
        super(TestTenantPost, self).setUp(config)

    def test_delete(self):
        uuid = 'c6b27903-e0af-43ac-80d9-6ea88e187537'
        result = self.delete(uuid)

        assert_that(result.status_code, equal_to(204))
        self.tenant_service.delete.assert_called_once_with(uuid)

    def test_invalid_posts(self):
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

    def test_get(self):
        self.tenant_service.count.side_effect = expected_total, expected_filtered = 5, 2
        self.tenant_service.list_.return_value = expected_items = [{'name': 'one'}, {'name': 'two'}]

        result = self.get()

        assert_that(result.status_code, equal_to(200))
        assert_that(
            json.loads(result.data),
            has_entries(
                'total', expected_total,
                'filtered', expected_filtered,
                'items', expected_items,
            ),
        )

    def delete(self, tenant_uuid):
        url = '{}/{}'.format(self.url, tenant_uuid)
        return self.app.delete(url, headers=self.headers)

    def get(self, **data):
        return self.app.get(self.url, query_string=data, headers=self.headers)

    def post(self, data):
        return self.app.post(self.url, data=json.dumps(data), headers=self.headers)
