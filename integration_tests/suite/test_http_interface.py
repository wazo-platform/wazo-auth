# -*- coding: utf-8 -*-
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import time
import os
import uuid
import logging

from datetime import datetime, timedelta

import requests
from hamcrest import assert_that
from hamcrest import calling
from hamcrest import contains_inanyorder
from hamcrest import contains_string
from hamcrest import equal_to
from hamcrest import has_entries
from hamcrest import has_items
from hamcrest import has_key
from hamcrest import has_length
from hamcrest import has_properties
from hamcrest import is_
from xivo_test_helpers.hamcrest.raises import raises

from xivo_test_helpers.hamcrest.uuid_ import uuid_
from xivo_test_helpers import until
from wazo_auth import database, exceptions
from .helpers.base import BaseTestCase, MockBackendTestCase

requests.packages.urllib3.disable_warnings()
logger = logging.getLogger(__name__)

ISO_DATETIME = '%Y-%m-%dT%H:%M:%S.%f'


def _new_token_id():
    return uuid.uuid4()


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
