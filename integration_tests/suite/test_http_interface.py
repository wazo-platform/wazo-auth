# -*- coding: utf-8 -*-
#
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
#
# SPDX-License-Identifier: GPL-3.0+

import time
import os
import uuid
import logging

from datetime import datetime, timedelta

import requests
from hamcrest import assert_that
from hamcrest import calling
from hamcrest import contains
from hamcrest import contains_inanyorder
from hamcrest import contains_string
from hamcrest import equal_to
from hamcrest import empty
from hamcrest import has_entries
from hamcrest import has_items
from hamcrest import has_key
from hamcrest import has_length
from hamcrest import has_properties
from hamcrest import is_
from hamcrest import none
from xivo_test_helpers.hamcrest.raises import raises
from xivo_auth_client import Client

from xivo_test_helpers.hamcrest.uuid_ import uuid_
from xivo_test_helpers import until
from wazo_auth import database, exceptions
from .helpers import fixtures
from .helpers.base import BaseTestCase, MockBackendTestCase

requests.packages.urllib3.disable_warnings()
logger = logging.getLogger(__name__)

ISO_DATETIME = '%Y-%m-%dT%H:%M:%S.%f'


def _new_token_id():
    return uuid.uuid4()


class TestPolicies(MockBackendTestCase):

    def tearDown(self):
        for policy in self.client.policies.list()['items']:
            self.client.policies.delete(policy['uuid'])

    def test_policies_creation(self):
        name, description, acl_templates = 'foobar', 'a test policy', ['dird.me.#', 'ctid-ng.#']
        response = self.client.policies.new(name, description, acl_templates)
        assert_that(response, has_entries({
            'uuid': uuid_(),
            'name': equal_to(name),
            'description': equal_to(description),
            'acl_templates': contains_inanyorder(*acl_templates)}))

        name = 'foobaz'
        response = self.client.policies.new(name)
        assert_that(response, has_entries({
            'uuid': uuid_(),
            'name': equal_to(name),
            'description': none(),
            'acl_templates': empty()}))

        assert_that(
            calling(self.client.policies.new).with_args(''),
            raises(requests.HTTPError))

    def test_list_policies(self):
        one = self.client.policies.new('one')
        two = self.client.policies.new('two')
        three = self.client.policies.new('three')

        response = self.client.policies.list(search='foobar')
        assert_that(response, has_entries({
            'total': equal_to(0),
            'items': empty()}))

        response = self.client.policies.list()
        assert_that(response, has_entries({
            'total': equal_to(3),
            'items': contains_inanyorder(one, two, three)}))

        response = self.client.policies.list(search='one')
        assert_that(response, has_entries({
            'total': equal_to(1),
            'items': contains_inanyorder(one)}))

        response = self.client.policies.list(order='name', direction='asc')
        assert_that(response, has_entries({
            'total': equal_to(3),
            'items': contains(one, three, two)}))

        response = self.client.policies.list(order='name', direction='asc', limit=1)
        assert_that(response, has_entries({
            'total': equal_to(3),
            'items': contains(one)}))

        response = self.client.policies.list(order='name', direction='asc', limit=1, offset=1)
        assert_that(response, has_entries({
            'total': equal_to(3),
            'items': contains(three)}))

    def test_get_policy(self):
        name, description, acl_templates = 'foobar', 'a test policy', ['dird.me.#', 'ctid-ng.#']
        policy = self.client.policies.new(name, description, acl_templates)

        response = self.client.policies.get(policy['uuid'])
        assert_that(response, equal_to(policy))

        unknown_uuid = str(uuid.uuid4())
        assert_that(
            calling(self.client.policies.get).with_args(unknown_uuid),
            raises(requests.HTTPError))

    def test_delete_policy(self):
        unknown_uuid = str(uuid.uuid4())
        assert_that(
            calling(self.client.policies.delete).with_args(unknown_uuid),
            raises(requests.HTTPError))

        name, description, acl_templates = 'foobar', 'a test policy', ['dird.me.#', 'ctid-ng.#']
        policy = self.client.policies.new(name, description, acl_templates)

        self.client.policies.delete(policy['uuid'])
        assert_that(
            calling(self.client.policies.delete).with_args(policy['uuid']),
            raises(requests.HTTPError))

    def test_edit_policy(self):
        unknown_uuid = str(uuid.uuid4())
        assert_that(
            calling(self.client.policies.edit).with_args(unknown_uuid, 'foobaz'),
            raises(requests.HTTPError))

        name, description, acl_templates = 'foobar', 'a test policy', ['dird.me.#', 'ctid-ng.#']
        policy = self.client.policies.new(name, description, acl_templates)

        response = self.client.policies.edit(policy['uuid'], 'foobaz')
        assert_that(response, has_entries({
            'uuid': equal_to(policy['uuid']),
            'name': equal_to('foobaz'),
            'description': none(),
            'acl_templates': empty()}))

    def test_add_acl_template(self):
        unknown_uuid = str(uuid.uuid4())
        assert_that(
            calling(self.client.policies.add_acl_template).with_args(unknown_uuid, '#'),
            raises(requests.HTTPError))

        name, description, acl_templates = 'foobar', 'a test policy', ['dird.me.#', 'ctid-ng.#']
        policy = self.client.policies.new(name, description, acl_templates)

        self.client.policies.add_acl_template(policy['uuid'], 'new.acl.template.#')

        expected_acl_templates = acl_templates + ['new.acl.template.#']
        response = self.client.policies.get(policy['uuid'])
        assert_that(response, has_entries({
            'uuid': equal_to(policy['uuid']),
            'name': equal_to(name),
            'description': equal_to(description),
            'acl_templates': contains_inanyorder(*expected_acl_templates)}))

    def test_remove_acl_template(self):
        unknown_uuid = str(uuid.uuid4())
        assert_that(
            calling(self.client.policies.remove_acl_template).with_args(unknown_uuid, 'foo'),
            raises(requests.HTTPError))

        name, description, acl_templates = 'foobar', 'a test policy', ['dird.me.#', 'ctid-ng.#']
        policy = self.client.policies.new(name, description, acl_templates)

        self.client.policies.remove_acl_template(policy['uuid'], 'ctid-ng.#')

        response = self.client.policies.get(policy['uuid'])
        assert_that(response, has_entries({
            'uuid': equal_to(policy['uuid']),
            'name': equal_to(name),
            'description': equal_to(description),
            'acl_templates': contains_inanyorder(*acl_templates[:-1])}))


class TestWazoUserBackend(MockBackendTestCase):

    def tearDown(self):
        for user in self.client.users.list()['items']:
            self.client.users.delete(user['uuid'])

    def test_token_creation(self):
        username, email, password = 'foobar', 'foobar@example.com', 's3cr37'
        user = self.client.users.new(username=username, email_address=email, password=password)

        response = self._post_token(username, password, backend='wazo_user')
        assert_that(
            response,
            has_entries(
                'token', uuid_(),
                'auth_id', user['uuid'],
                'acls', has_items(
                    'confd.#',
                    'plugind.#',
                ),
            ),
        )

        assert_that(
            calling(self._post_token).with_args(username, 'not-our-password', backend='wazo_user'),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 401)),
            ),
        )

        assert_that(
            calling(self._post_token).with_args('not-our-user', password, backend='wazo_user'),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 401)),
            ),
        )


class TestCoreMockBackend(MockBackendTestCase):

    def test_that_the_xivo_uuid_is_included_in_POST_response(self):
        response = self._post_token('foo', 'bar')

        xivo_uuid = response['xivo_uuid']
        assert_that(xivo_uuid, equal_to('the-predefined-xivo-uuid'))

    def test_that_head_with_a_valid_token_returns_204(self):
        token = self._post_token('foo', 'bar')['token']

        assert_that(self._is_valid(token))

    def test_that_head_with_an_invalid_token_returns_404(self):
        assert_that(self._is_valid('abcdef'), is_(False))

    def test_backends(self):
        url = 'https://{}:{}/0.1/backends'.format(self.get_host(), self.service_port(9497, 'auth'))
        response = requests.get(url, verify=False)
        backends = ['mock', 'mock_with_uuid', 'broken_init', 'broken_verify_password', 'wazo_user']
        assert_that(response.json()['data'], contains_inanyorder(*backends))

    def test_that_get_returns_the_auth_id(self):
        token = self._post_token('foo', 'bar')['token']

        response = self._get_token(token)

        assert_that(response['auth_id'], equal_to('a-mocked-uuid'))

    def test_that_get_returns_the_xivo_uuid_in_the_response(self):
        token = self._post_token('foo', 'bar')['token']

        response = self._get_token(token)

        xivo_uuid = response['xivo_uuid']
        assert_that(xivo_uuid, equal_to('the-predefined-xivo-uuid'))

    def test_that_get_returns_the_xivo_user_uuid(self):
        token = self._post_token('foo', 'bar')['token']

        response = self._get_token(token)

        assert_that(response, has_key('xivo_user_uuid'))

    def test_that_get_does_not_work_after_delete(self):
        token = self._post_token('foo', 'bar')['token']
        self._delete_token(token)
        self._get_token_with_expected_exception(token, status_code=404, msg='No such token')

    def test_that_deleting_unexistant_token_returns_200(self):
        self._delete_token(_new_token_id())  # no exception

    def test_that_the_wrong_password_returns_401(self):
        self._post_token_with_expected_exception('foo', 'not_bar', status_code=401)

    def test_that_the_right_credentials_return_a_token_with_datas(self):
        response = self._post_token('foo', 'bar', backend='mock_with_uuid')
        content = response
        token = content['token']
        auth_id = content['auth_id']
        xivo_user_uuid = content['xivo_user_uuid']
        acls = content['acls']

        assert_that(token, has_length(36))
        assert_that(auth_id, equal_to('a-mocked-auth-id'))
        assert_that(xivo_user_uuid, equal_to('a-mocked-xivo-user-uuid'))
        assert_that(acls, contains_inanyorder('foo', 'bar'))

    def test_that_an_unknown_type_returns_a_401(self):
        self._post_token_with_expected_exception('foo', 'not_bar', 'unexistant_backend', status_code=401)

    def test_that_a_broken_backend_returns_a_401(self):
        self._post_token_with_expected_exception('foo', 'not_bar', 'broken_verify_password', status_code=401)

    def test_that_no_type_returns_400(self):
        url = 'https://{}:{}/0.1/token'.format(self.get_host(), self.service_port(9497, 'auth'))
        s = requests.Session()
        s.headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        s.auth = requests.auth.HTTPBasicAuth('foo', 'bar')

        response = s.post(url, verify=False)

        assert_that(response.status_code, equal_to(400))

    def test_the_expiration_argument(self):
        token_data = self._post_token('foo', 'bar', expiration=2)

        creation_time = datetime.strptime(token_data['issued_at'], ISO_DATETIME)
        expiration_time = datetime.strptime(token_data['expires_at'], ISO_DATETIME)
        utc_creation_time = datetime.strptime(token_data['utc_issued_at'], ISO_DATETIME)
        utc_expiration_time = datetime.strptime(token_data['utc_expires_at'], ISO_DATETIME)

        utcoffset = timedelta(hours=1)  # UTC+1 is hardcoded in the docker-compose file

        expiration = expiration_time - creation_time
        utc_expiration = utc_expiration_time - utc_creation_time

        assert_that(expiration.seconds, equal_to(2))
        assert_that(utc_expiration.seconds, equal_to(2))
        assert_that(utc_expiration_time - expiration_time, equal_to(utcoffset))
        assert_that(utc_creation_time - creation_time, equal_to(utcoffset))

    def test_that_expired_tokens_are_not_leaked_in_the_db(self):
        token_data = self._post_token('foo', 'bar', expiration=1)

        until.false(self._is_token_in_the_db, token_data['token'], tries=5, interval=1)

    def test_the_expiration_argument_as_a_string(self):
        self._post_token_with_expected_exception(
            'foo', 'bar', expiration="string",
            status_code=400)

    def test_negative_expiration(self):
        self._post_token_with_expected_exception(
            'foo', 'bar', expiration=-1,
            status_code=400)

    def test_that_expired_tokens_are_not_valid(self):
        token = self._post_token('foo', 'bar', expiration=1)['token']

        time.sleep(2)

        assert_that(self._is_valid(token), equal_to(False))

    def test_that_invalid_unicode_acl_returns_403(self):
        token = self._post_token('foo', 'bar')['token']
        assert_that(self._is_valid(token, acls='éric'), is_(False))

    def test_that_unauthorized_acls_on_HEAD_return_403(self):
        token = self._post_token('foo', 'bar')['token']
        assert_that(self._is_valid(token, acls='confd'), is_(False))

    def test_that_unauthorized_acls_on_GET_return_403(self):
        token = self._post_token('foo', 'bar')['token']
        self._get_token_with_expected_exception(token, acls='confd', status_code=403)

    def test_that_authorized_acls_on_HEAD_return_204(self):
        token = self._post_token('foo', 'bar')['token']
        assert_that(self._is_valid(token, acls='foo'))

    def test_that_authorized_acls_on_GET_return_200(self):
        token = self._post_token('foo', 'bar')['token']
        self._get_token(token, acls='foo')  # no exception

    def _is_token_in_the_db(self, token):
        db_uri = os.getenv('DB_URI', 'postgresql://asterisk:proformatique@localhost:{port}')
        dao = database._TokenDAO(db_uri.format(port=self.service_port(5432, 'postgres')))
        try:
            dao.get(token)
            return True
        except exceptions.UnknownTokenException:
            return False


class TestNoSSLCertificate(BaseTestCase):

    asset = 'no_ssl_certificate'

    def test_that_wazo_auth_stops_if_not_readable_ssl_certificate(self):
        self._assert_that_wazo_auth_is_stopping()

        log = self.service_logs('auth')
        assert_that(log, contains_string("No such file or directory: '/data/_common/ssl/no_server.crt'"))


class TestNoSSLKey(BaseTestCase):

    asset = 'no_ssl_key'

    def test_that_wazo_auth_stops_if_not_readable_ssl_key(self):
        self._assert_that_wazo_auth_is_stopping()

        log = self.service_logs('auth')
        assert_that(log, contains_string("No such file or directory: '/data/_common/ssl/no_server.key'"))


class TestTenants(MockBackendTestCase):

    @fixtures.http_tenant(name='foobar')
    def test_post(self, tenant):
        name = 'foobar'

        assert_that(
            tenant,
            has_entries(
                'uuid', uuid_(),
                'name', name,
            ),
        )

        assert_that(
            calling(self.client.tenants.new).with_args(name=name),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 409)),
            ),
        )

    @fixtures.http_tenant()
    def test_delete(self, tenant):
        self.client.tenants.delete(tenant['uuid'])

        assert_that(
            calling(self.client.tenants.delete).with_args(tenant['uuid']),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 404)),
            )
        )

    @fixtures.http_tenant()
    def test_get_one(self, tenant):
        result = self.client.tenants.get(tenant['uuid'])
        assert_that(result, equal_to(tenant))

        assert_that(
            calling(self.client.tenants.get).with_args('unknown-uuid'),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 404)),
            )
        )

    @fixtures.http_tenant(name='foobar')
    @fixtures.http_tenant(name='foobaz')
    @fixtures.http_tenant(name='foobarbaz')
    def test_list(self, foobarbaz, foobaz, foobar):
        result = self.client.tenants.list()
        assert_that(
            result,
            has_entries(
                'items', contains_inanyorder(
                    equal_to(foobaz),
                    equal_to(foobar),
                    equal_to(foobarbaz),
                ),
                'total', 3,
                'filtered', 3,
            ),
            'no args',
        )

        result = self.client.tenants.list(uuid=foobaz['uuid'])
        assert_that(
            result,
            has_entries(
                'items', contains_inanyorder(
                    equal_to(foobaz),
                ),
                'total', 3,
                'filtered', 1,
            ),
            'strict match',
        )

        result = self.client.tenants.list(search='bar')
        assert_that(
            result,
            has_entries(
                'items', contains_inanyorder(
                    equal_to(foobar),
                    equal_to(foobarbaz),
                ),
                'total', 3,
                'filtered', 2,
            ),
            'search',
        )

        result = self.client.tenants.list(limit=1, offset=1, order='name')
        assert_that(
            result,
            has_entries('items', contains(
                equal_to(foobarbaz),
            )),
            'limit and offset',
        )

        result = self.client.tenants.list(order='name', direction='desc')
        assert_that(
            result,
            has_entries('items', contains(
                equal_to(foobaz),
                equal_to(foobarbaz),
                equal_to(foobar),
            )),
            'sort',
        )

        assert_that(
            calling(self.client.tenants.list).with_args(limit='foo'),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 400)),
            ),
            'invalid limit',
        )
        assert_that(
            calling(self.client.tenants.list).with_args(offset=-1),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 400)),
            ),
            'invalid offset',
        )


class TestUsers(MockBackendTestCase):

    def tearDown(self):
        for user in self.client.users.list()['items']:
            self.client.users.delete(user['uuid'])

    def test_delete(self):
        unknown_uuid = '67e7a4e9-8389-40df-b76d-ea6dea79b0ca'
        assert_that(
            calling(self.client.users.delete).with_args(unknown_uuid),
            raises(requests.HTTPError),
        )

        username, email, password = 'foobar', 'foobar@example.com', 's3cr37'
        user = self.client.users.new(username=username, email_address=email, password=password)

        self.client.users.delete(user['uuid'])
        assert_that(
            calling(self.client.policies.delete).with_args(user['uuid']),
            raises(requests.HTTPError),
        )

    def test_post(self):
        username, email, password = 'foobar', 'foobar@example.com', 's3cr37'
        user = self.client.users.new(username=username, email_address=email, password=password)

        assert_that(
            user,
            has_entries(
                'uuid', uuid_(),
                'username', username,
                'emails', contains_inanyorder(
                    has_entries(
                        'address', 'foobar@example.com',
                        'main', True,
                        'confirmed', False,
                    ),
                ),
            ),
        )

    def test_list(self):
        foo = ('foo', 'foo@example.com', 's3cr37')
        bar = ('bar', 'bar@example.com', '$$bar$$')
        baz = ('baz', 'baz@example.com', '5fb9359e-4135-4a0b-aaed-97ae6a0b140d')

        for username, email, password in (foo, bar, baz):
            self.client.users.new(username=username, email_address=email, password=password)

        assert_that(
            self.client.users.list(search='ba'),
            has_entries(
                'total', 3,
                'filtered', 2,
                'items', contains_inanyorder(
                    has_entries('username', 'bar'),
                    has_entries('username', 'baz'),
                ),
            ),
        )

        assert_that(
            self.client.users.list(username='baz'),
            has_entries(
                'total', 3,
                'filtered', 1,
                'items', contains_inanyorder(
                    has_entries('username', 'baz'),
                ),
            ),
        )

        assert_that(
            self.client.users.list(order='username', direction='desc'),
            has_entries(
                'total', 3,
                'filtered', 3,
                'items', contains(
                    has_entries('username', 'foo'),
                    has_entries('username', 'baz'),
                    has_entries('username', 'bar'),
                ),
            ),
        )

        assert_that(
            self.client.users.list(limit=1, offset=1, order='username', direction='asc'),
            has_entries(
                'total', 3,
                'filtered', 3,
                'items', contains(
                    has_entries('username', 'baz'),
                ),
            ),
        )

    def test_get(self):
        username, email, password = 'foobar', 'foobar@example.com', 's3cr37'
        user = self.client.users.new(username=username, email_address=email, password=password)

        result = self.client.users.get(user['uuid'])
        assert_that(
            result,
            has_entries(
                'uuid', uuid_(),
                'username', username,
                'emails', contains_inanyorder(
                    has_entries(
                        'address', email,
                        'confirmed', False,
                        'main', True,
                    ),
                ),
            ),
        )

    @fixtures.http_user(username='foo', password='bar')
    @fixtures.http_policy(name='two', acl_templates=['acl.one.{{ username }}', 'acl.two'])
    @fixtures.http_policy(name='one', acl_templates=['this.is.a.test.acl'])
    def test_user_policy(self, policy_1, policy_2, user):
        result = self.client.users.get_policies(user['uuid'])
        assert_that(
            result,
            has_entries(
                'total', 0,
                'items', empty(),
                'filtered', 0,
            ),
            'not associated',
        )

        self.client.users.add_policy(user['uuid'], policy_1['uuid'])
        self.client.users.add_policy(user['uuid'], policy_2['uuid'])

        user_client = Client(
            self.get_host(), port=self.service_port(9497, 'auth'), verify_certificate=False,
            username='foo', password='bar')
        token_data = user_client.token.new('wazo_user', expiration=5)
        assert_that(
            token_data,
            has_entries(
                'acls', has_items(
                    'acl.one.foo',
                    'this.is.a.test.acl',
                    'acl.two',
                ),
            ),
            'generated acl',
        )

        self.client.users.remove_policy(user['uuid'], policy_2['uuid'])

        assert_that(
            calling(
                self.client.users.add_policy
            ).with_args('8ee4e6a3-533e-4b00-99b2-33b2e55102f2', policy_2['uuid']),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 404)),
            ),
            'unknown user',
        )

        assert_that(
            calling(
                self.client.users.add_policy
            ).with_args(user['uuid'], '113bb403-7914-4685-a0ec-330676e61f7c'),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 404)),
            ),
            'unknown policy',
        )

        result = self.client.users.get_policies(user['uuid'])
        assert_that(
            result,
            has_entries(
                'total', 1,
                'items', contains(has_entries('name', 'one')),
                'filtered', 1,
            ),
            'not associated',
        )

        result = self.client.users.get_policies(user['uuid'], search='two')
        assert_that(
            result,
            has_entries(
                'total', 1,
                'items', empty(),
                'filtered', 0,
            ),
            'not associated',
        )

        self.client.users.remove_policy(user['uuid'], policy_1['uuid'])

        assert_that(
            calling(
                self.client.users.remove_policy
            ).with_args(user['uuid'], policy_1['uuid']),
            raises(requests.HTTPError).matching(
                has_properties('response', has_properties('status_code', 404)),
            ),
            'no association found',
        )
