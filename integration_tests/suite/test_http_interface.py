# -*- coding: utf-8 -*-
#
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
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
from hamcrest import has_key
from hamcrest import has_length
from hamcrest import is_
from hamcrest import none
from hamcrest import raises
from xivo_auth_client import Client

from xivo_test_helpers.asset_launching_test_case import AssetLaunchingTestCase
from xivo_test_helpers.hamcrest.uuid_ import uuid_
from xivo_test_helpers import until
from wazo_auth import database, exceptions

requests.packages.urllib3.disable_warnings()
logger = logging.getLogger(__name__)

ISO_DATETIME = '%Y-%m-%dT%H:%M:%S.%f'

HOST = os.getenv('WAZO_AUTH_TEST_HOST', 'localhost')


def _new_token_id():
    return uuid.uuid4()


class _BaseTestCase(AssetLaunchingTestCase):

    assets_root = os.path.join(os.path.dirname(__file__), '..', 'assets')
    service = 'auth'

    @classmethod
    def setUpClass(cls):
        super(_BaseTestCase, cls).setUpClass()

    def _post_token(self, username, password, backend=None, expiration=None):
        port = self.service_port(9497, 'auth')
        client = Client(HOST, port, username=username, password=password, verify_certificate=False)
        backend = backend or 'mock'
        args = {}
        if expiration:
            args['expiration'] = expiration
        return client.token.new(backend, **args)

    def _post_token_with_expected_exception(self, username, password, backend=None, expiration=None, status_code=None, msg=None):
        try:
            self._post_token(username, password, backend, expiration)
        except requests.HTTPError as e:
            if status_code:
                assert_that(e.response.status_code, equal_to(status_code))
            if msg:
                assert_that(e.response.json()['reason'][0], equal_to(msg))
        else:
            self.fail('Should have raised an exception')

    def _get_token(self, token, acls=None):
        port = self.service_port(9497, 'auth')
        client = Client(HOST, port, verify_certificate=False)
        args = {}
        if acls:
            args['required_acl'] = acls
        return client.token.get(token, **args)

    def _get_token_with_expected_exception(self, token, acls=None, status_code=None, msg=None):
        try:
            self._get_token(token, acls)
        except requests.HTTPError as e:
            if status_code:
                assert_that(e.response.status_code, equal_to(status_code))
            if msg:
                assert_that(e.response.json()['reason'][0], equal_to(msg))
        else:
            self.fail('Should have raised an exception')

    def _delete_token(self, token):
        port = self.service_port(9497, 'auth')
        client = Client(HOST, port, verify_certificate=False)
        return client.token.revoke(token)

    def _is_valid(self, token, acls=None):
        port = self.service_port(9497, 'auth')
        client = Client(HOST, port, verify_certificate=False)
        args = {}
        if acls:
            args['required_acl'] = acls
        return client.token.is_valid(token, **args)

    def _assert_that_wazo_auth_is_stopping(self):
        for _ in range(5):
            if not self.service_status('auth')['State']['Running']:
                break
            time.sleep(0.2)
        else:
            self.fail('wazo-auth did not stop')


class TestPolicies(_BaseTestCase):

    asset = 'mock_backend'

    def setUp(self):
        super(TestPolicies, self).setUp()
        port = self.service_port(9497, 'auth')
        self.client = Client(HOST, port, username='foo', password='bar', verify_certificate=False)
        token = self.client.token.new(backend='mock', expiration=3600)['token']
        self.client.set_token(token)

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


class TestCoreMockBackend(_BaseTestCase):

    asset = 'mock_backend'

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
        url = 'https://{}:{}/0.1/backends'.format(HOST, self.service_port(9497, 'auth'))
        response = requests.get(url, verify=False)

        assert_that(response.json()['data'],
                    contains_inanyorder('mock', 'mock_with_uuid', 'broken_init', 'broken_verify_password'))

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
        url = 'https://{}:{}/0.1/token'.format(HOST, self.service_port(9497, 'auth'))
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
        crud = database._TokenCRUD(db_uri.format(port=self.service_port(5432, 'postgres')))
        try:
            crud.get(token)
            return True
        except exceptions.UnknownTokenException:
            return False


class TestNoSSLCertificate(_BaseTestCase):

    asset = 'no_ssl_certificate'

    def test_that_wazo_auth_stops_if_not_readable_ssl_certificate(self):
        self._assert_that_wazo_auth_is_stopping()

        log = self.service_logs('auth')
        assert_that(log, contains_string("No such file or directory: '/data/_common/ssl/no_server.crt'"))


class TestNoSSLKey(_BaseTestCase):

    asset = 'no_ssl_key'

    def test_that_wazo_auth_stops_if_not_readable_ssl_key(self):
        self._assert_that_wazo_auth_is_stopping()

        log = self.service_logs('auth')
        assert_that(log, contains_string("No such file or directory: '/data/_common/ssl/no_server.key'"))


class TestUsers(_BaseTestCase):

    asset = 'mock_backend'

    def setUp(self):
        super(TestUsers, self).setUp()
        port = self.service_port(9497, 'auth')
        self.client = Client(HOST, port, username='foo', password='bar', verify_certificate=False)
        token = self.client.token.new(backend='mock', expiration=3600)['token']
        self.client.set_token(token)

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
