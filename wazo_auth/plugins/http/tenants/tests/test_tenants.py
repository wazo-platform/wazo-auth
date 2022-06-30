# Copyright 2017-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json

from unittest.mock import ANY, Mock, patch, sentinel as s

from hamcrest import assert_that, equal_to, has_entries, has_value, starts_with
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
            ('name', {'name': 42, 'slug': 'abc'}),
            ('name', {'name': 100 * 'foobar', 'slug': 'abc'}),
            ('slug', {'slug': 'a-b'}),
            ('slug', {'slug': 'a b'}),
            ('slug', {'slug': False}),
            ('slug', {'slug': 0}),
        ]

        for field, invalid_data in invalid_datas:
            result = self.post(invalid_data)
            assert_that(result.status_code, equal_to(400), invalid_data)
            assert_that(
                result.json,
                has_entries(
                    error_id='invalid-data',
                    message=ANY,
                    resource='tenants',
                    details=has_entries(
                        field,
                        has_entries(constraint_id=ANY, constraint=ANY, message=ANY),
                    ),
                ),
                invalid_data,
            )

    @patch('wazo_auth.plugins.http.tenants.http.TenantDetector')
    def test_that_validated_args_are_passed_to_the_service(self, TenantDetector):
        TenantDetector.autodetect.return_value = Mock(uuid=s.tenant_uuid)

        body = {
            'name': 'foobar',
            'slug': 'slug',
            'ignored': True,
            'domain_names': ['wazo.io'],
        }
        self.tenant_service.new.return_value = {
            'name': 'foobar',
            'uuid': '022035fe-f5e5-4c16-bd5f-8fea8f4c9d08',
        }

        result = self.post(body)

        assert_that(result.status_code, equal_to(200))
        assert_that(result.json, equal_to(self.tenant_service.new.return_value))
        self.tenant_service.new.assert_called_once_with(
            uuid=None,
            name='foobar',
            slug='slug',
            phone=None,
            contact_uuid=None,
            parent_uuid=s.tenant_uuid,
            domain_names=['wazo.io'],
            address=dict(
                line_1=None,
                line_2=None,
                city=None,
                state=None,
                zip_code=None,
                country=None,
            ),
        )

    @patch('wazo_auth.plugins.http.tenants.http.TenantDetector')
    def test_that_empty_tenant_addresses_return_400(self, TenantDetector):
        TenantDetector.autodetect.return_value = Mock(uuid=s.tenant_uuid)

        invalid_datas = [
            (
                'address',
                {
                    'address': {
                        'line_1': 'xxx',
                        'line_2': 'xxx',
                        'city': 'Montreal',
                        'state': '',
                        'country': 'Canada',
                        'zip_code': 'xxx',
                    }
                },
            ),
        ]

        for field, invalid_data in invalid_datas:
            result = self.post(invalid_data)
            assert_that(result.status_code, equal_to(400), invalid_data)
            assert_that(
                result.json,
                has_entries(
                    error_id='invalid-data',
                    message=starts_with('Length must be between'),
                    resource='tenants',
                    details=has_entries(
                        address=has_entries(
                            state=has_entries(
                                constraint_id='length',
                                constraint=ANY,
                                message=starts_with('Length must be between'),
                            ),
                        ),
                    ),
                ),
                invalid_data,
            )

    @patch('wazo_auth.plugins.http.tenants.http.TenantDetector')
    def test_that_tenant_with_invalid_domain_names_returns_400(self, TenantDetector):
        TenantDetector.autodetect.return_value = Mock(uuid=s.tenant_uuid)

        invalid_datas = [
            ('domain_names', {'domain_names': ['-wazo.io']}),
            ('domain_names', {'domain_names': [' wazo.io']}),
            ('domain_names', {'domain_names': ['#']}),
            ('domain_names', {'domain_names': ['123']}),
            ('domain_names', {'domain_names': ['wazo .io']}),
            ('domain_names', {'domain_names': ['wazo.io-']}),
            ('domain_names', {'domain_names': ['wazo']}),
            ('domain_names', {'domain_names': ['=wazo.io']}),
            ('domain_names', {'domain_names': ['+wazo.io']}),
            ('domain_names', {'domain_names': ['_wazo.io']}),
            ('domain_names', {'domain_names': ['wazo_io']}),
            ('domain_names', {'domain_names': ['wazo_io  ']}),
            ('domain_names', {'domain_names': ['']}),
        ]

        for field, invalid_data in invalid_datas:
            result = self.post(invalid_data)
            assert_that(result.status_code, equal_to(400), invalid_data)
            assert_that(
                result.json,
                has_entries(
                    error_id='invalid-data',
                    message=ANY,
                    resource='tenants',
                    details=has_entries(
                        field,
                        has_value(
                            has_entries(
                                constraint_id='regex',
                                constraint=ANY,
                                message='String does not match expected pattern.',
                            ),
                        ),
                    ),
                ),
                invalid_data,
            )

        invalid_data = {'domain_names': [None]}
        result = self.post(invalid_data)
        assert_that(result.status_code, equal_to(400), invalid_data)
        assert_that(
            result.json,
            has_entries(
                error_id='invalid-data',
                resource='tenants',
                details=has_entries(
                    domain_names=has_value(has_entries(constraint_id='not_null')),
                ),
            ),
            invalid_data,
        )

        invalid_domains_types = [
            ('domain_names', {'domain_names': None}),
            ('domain_names', {'domain_names': True}),
            ('domain_names', {'domain_names': False}),
            ('domain_names', {'domain_names': 'wazo.community'}),
            ('domain_names', {'domain_names': 42}),
            ('domain_names', {'domain_names': {'name': 'wazo.community'}}),
        ]

        for field, invalid_data in invalid_domains_types:
            result = self.post(invalid_data)
            assert_that(result.status_code, equal_to(400), invalid_data)
            assert_that(
                result.json,
                has_entries(
                    error_id='invalid-data',
                    message=ANY,
                    resource='tenants',
                    details=has_entries(
                        field,
                        has_entries(constraint_id=ANY, message=ANY),
                    ),
                ),
                invalid_data,
            )

    @patch('wazo_auth.plugins.http.tenants.http.TenantDetector')
    def test_that_post_with_duplicate_domain_names_returns_unique_ones(
        self, TenantDetector
    ):
        TenantDetector.autodetect.return_value = Mock(uuid=s.tenant_uuid)

        duplicate_domain_names = [
            'wazo.io',
            'wazo.io',
            'gmail.com',
            'gmail.com',
            'gmail.ca',
            'wazo.io',
        ]

        body = {
            'name': 'foobar',
            'slug': 'slug',
            'ignored': True,
            'domain_names': duplicate_domain_names,
        }
        self.tenant_service.new.return_value = {
            'name': 'foobar',
            'uuid': '022035fe-f5e5-4c16-bd5f-8fea8f4c9d08',
        }

        result = self.post(body)

        assert_that(result.status_code, equal_to(200))
        assert_that(result.json, equal_to(self.tenant_service.new.return_value))
        self.tenant_service.new.assert_called_once_with(
            uuid=None,
            name='foobar',
            slug='slug',
            phone=None,
            contact_uuid=None,
            parent_uuid=s.tenant_uuid,
            domain_names=sorted(list(set(duplicate_domain_names))),
            address=dict(
                line_1=None,
                line_2=None,
                city=None,
                state=None,
                zip_code=None,
                country=None,
            ),
        )

    @patch('wazo_auth.plugins.http.tenants.http.TenantDetector')
    def test_post_valid_domain_names(self, TenantDetector):
        TenantDetector.autodetect.return_value = Mock(uuid=s.tenant_uuid)

        valid_domain_names = [
            ['mail.yahoo.com'],
            ['mail.yahoo.fr'],
            ['trademark247.com'],
            ['github.com'],
            ['stackoverflow.com'],
            ['tesla.ca'],
            ['dev.atlassian.net'],
            ['shopify.ca'],
            ['whatever.42'],
            ['gmail.com'],
        ]

        for valid_data in valid_domain_names:
            body = {
                'name': 'foobar',
                'slug': 'slug',
                'ignored': True,
                'domain_names': valid_data,
            }
            self.tenant_service.new.return_value = {
                'name': 'foobar',
                'uuid': '022035fe-f5e5-4c16-bd5f-8fea8f4c9d08',
                'domain_names': valid_data,
            }
            result = self.post(body)
            assert_that(result.status_code, equal_to(200))
            assert_that(result.json, equal_to(self.tenant_service.new.return_value))

    def post(self, data):
        return self.app.post(self.url, data=json.dumps(data), headers=self.headers)
