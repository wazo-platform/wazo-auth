# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest import TestCase

from hamcrest import assert_that, equal_to, has_entries, any_of
from flask import Flask
from flask_restful import Api
from mock import ANY, Mock, sentinel as s, patch

from xivo import plugin_helpers

from ..config import _DEFAULT_CONFIG
from .. import services

initialized = False


class HTTPAppTestCase(TestCase):

    headers = {'content-type': 'application/json'}

    def setUp(self, config):
        self.user_service = Mock(services.UserService)
        self.policy_service = Mock()
        self.tenant_service = Mock(services.TenantService)
        token_service = Mock()
        group_service = Mock()
        self.email_service = Mock(services.EmailService)
        external_auth_service = Mock()
        self.tokens = Mock()
        self.users = Mock()
        self.session_service = Mock()
        self.template_formatter = Mock()

        app = Flask('wazo-auth')
        app.config['token_service'] = token_service
        app.config['user_service'] = self.user_service
        api = Api(app, prefix='/0.1')
        dependencies = {
            'api': api,
            'config': config,
            'backends': s.backends,
            'policy_service': self.policy_service,
            'token_service': token_service,
            'user_service': self.user_service,
            'tenant_service': self.tenant_service,
            'group_service': group_service,
            'email_service': self.email_service,
            'external_auth_service': external_auth_service,
            'tokens': self.tokens,
            'users': self.users,
            'session_service': self.session_service,
            'template_formatter': self.template_formatter,
        }
        plugin_helpers.load(
            namespace='wazo_auth.http',
            names=config['enabled_http_plugins'],
            dependencies=dependencies,
        )
        self.app = app.test_client()


TENANT = '00000000-0000-0000-0000-000000000000'


@patch(
    'wazo_auth.plugins.http.users.http.Tenant',
    Mock(autodetect=Mock(return_value=Mock(uuid=TENANT))),
)
class TestUserResource(HTTPAppTestCase):
    def setUp(self):
        super().setUp(_DEFAULT_CONFIG)
        self.url = '/0.1/users'

    def test_that_creating_a_user_calls_the_service(self):
        username, password, email_address = 'foobar', 'b3h01D', 'foobar@example.com'
        uuid = '839a34a1-4027-4046-ad22-af086014874e'
        body = {
            'username': username,
            'password': password,
            'email_address': email_address,
        }
        self.user_service.new_user.return_value = {
            'uuid': uuid,
            'username': username,
            'email_address': email_address,
        }

        result = self.app.post(self.url, json=body)

        assert_that(result.status_code, equal_to(200))
        self.user_service.new_user.assert_called_once_with(
            email_confirmed=True,
            firstname=None,
            lastname=None,
            enabled=True,
            purpose='user',
            tenant_uuid=TENANT,
            **body
        )

        assert_that(
            result.json,
            has_entries(
                'uuid', uuid, 'username', username, 'email_address', email_address
            ),
        )

    def test_that_ommiting_a_required_fields_returns_400(self):
        username, password, email_address = 'foobar', 'b3h01D', 'foobar@example.com'
        valid_body = {
            'username': username,
            'password': password,
            'email_address': email_address,
        }

        for field in ['username']:
            body = dict(valid_body)
            del body[field]

            result = self.app.post(self.url, json=body)

            assert_that(result.status_code, equal_to(400), field)
            assert_that(
                result.json,
                has_entries(
                    'error_id',
                    'invalid-data',
                    'message',
                    'Missing data for required field.',
                    'resource',
                    'users',
                    'details',
                    {
                        field: {
                            'constraint_id': 'required',
                            'constraint': 'required',
                            'message': ANY,
                        }
                    },
                ),
                field,
            )

    def test_that_an_empty_body_returns_400(self):
        result = self.app.post(self.url, json='null')

        assert_that(result.status_code, equal_to(400))
        assert_that(result.json, has_entries('error_id', 'invalid-data'))

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

            result = self.app.post(self.url, json=body)

            assert_that(result.status_code, equal_to(400), field)
            assert_that(
                result.json,
                has_entries(
                    'error_id',
                    'invalid-data',
                    'resource',
                    'users',
                    'details',
                    has_entries(
                        field, has_entries('constraint_id', any_of('length', 'type'))
                    ),
                ),
                field,
            )

    def test_that_null_fields_are_not_valid(self):
        username = 'foobar'
        valid_body = {'username': username}

        for field in ('username',):
            body = dict(valid_body)
            body[field] = None

            result = self.app.post(self.url, json=body)

            assert_that(result.status_code, equal_to(400), field)
            assert_that(
                result.json,
                has_entries(
                    'error_id',
                    'invalid-data',
                    'resource',
                    'users',
                    'details',
                    has_entries(field, has_entries('constraint_id', 'not_null')),
                ),
                field,
            )

    def test_user_list(self):
        params = {
            'direction': 'desc',
            'order': 'username',
            'limit': 5,
            'offset': 42,
            'search': 'foo',
            'uuid': '5941aabb-9e4a-4d2e-9e1e-7f9929354458',
        }
        expected_total, expected_filtered = 100, 1
        expected_result = [
            {
                'username': 'foobar',
                'email_address': 'foobar@example.com',
                'uuid': '5941aabb-9e4a-4d2e-9e1e-7f9929354458',
            }
        ]
        self.user_service.list_users.return_value = expected_result
        self.user_service.count_users.side_effect = [expected_total, expected_filtered]

        result = self.app.get(self.url, query_string=params)

        assert_that(result.status_code, equal_to(200))
        assert_that(
            result.json,
            has_entries(
                'total',
                expected_total,
                'filtered',
                expected_filtered,
                'items',
                expected_result,
            ),
        )

    def test_user_list_invalid_list_params(self):
        params = {
            'direction': 'desc',
            'order': 'email_address',
            'limit': 5,
            'offset': 42,
            'search': 'foo',
            'uuid': '5941aabb-9e4a-4d2e-9e1e-7f9929354458',
        }

        invalid_params = dict(params)
        invalid_params['limit'] = -1
        result = self.app.get(self.url, query_string=invalid_params)
        assert_that(result.status_code, equal_to(400))
        assert_that(
            result.json,
            has_entries(
                'error_id', 'invalid-list-param', 'message', has_entries('limit', ANY)
            ),
        )

        invalid_params = dict(params)
        invalid_params['offset'] = -1
        result = self.app.get(self.url, query_string=invalid_params)
        assert_that(result.status_code, equal_to(400))
        assert_that(
            result.json,
            has_entries(
                'error_id', 'invalid-list-param', 'message', has_entries('offset', ANY)
            ),
        )

        invalid_params = dict(params)
        invalid_params['direction'] = -1
        result = self.app.get(self.url, query_string=invalid_params)
        assert_that(result.status_code, equal_to(400))
        assert_that(
            result.json,
            has_entries(
                'error_id',
                'invalid-list-param',
                'message',
                has_entries('direction', ANY),
            ),
        )

        invalid_params = dict(params)
        invalid_params['order'] = ''
        result = self.app.get(self.url, query_string=invalid_params)
        assert_that(result.status_code, equal_to(400))
        assert_that(
            result.json,
            has_entries(
                'error_id', 'invalid-list-param', 'message', has_entries('order', ANY)
            ),
        )

    def test_user_get(self):
        uuid = '5730c531-5e47-4de6-be60-c3e28de00de4'
        url = '/'.join([self.url, uuid])
        expected_result = {
            'username': 'foobar',
            'uuid': uuid,
            'emails': [
                {'address': 'foobar@example.com', 'confirmed': True, 'main': True}
            ],
        }
        self.user_service.get_user.return_value = expected_result

        result = self.app.get(url)

        assert_that(result.json, equal_to(expected_result))

    def test_user_delete(self):
        uuid = '5730c531-5e47-4de6-be60-c3e28de00de4'
        url = '/'.join([self.url, uuid])

        result = self.app.delete(url)

        assert_that(result.status_code, equal_to(204))
