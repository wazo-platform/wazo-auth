# Copyright 2015-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time
import os
import uuid
import logging

from datetime import datetime, timedelta

import requests
from mock import ANY
from hamcrest import (
    assert_that,
    calling,
    contains_inanyorder,
    contains_string,
    equal_to,
    has_entries,
    has_key,
    is_,
    not_,
    raises,
)

from xivo_test_helpers import until
from xivo_test_helpers.hamcrest.uuid_ import uuid_
from wazo_auth import exceptions
from wazo_auth.database import models
from wazo_auth.database.queries.token import TokenDAO
from wazo_auth.database.queries.session import SessionDAO
from .helpers.base import (
    AuthLaunchingTestCase,
    WazoAuthTestCase,
)
from .helpers import fixtures

requests.packages.urllib3.disable_warnings()
logger = logging.getLogger(__name__)

ISO_DATETIME = '%Y-%m-%dT%H:%M:%S.%f'


def _new_token_id():
    return uuid.uuid4()


class TestCore(WazoAuthTestCase):

    def setUp(self):
        self.user = self.client.users.new(username='foo', password='bar')

    def tearDown(self):
        self.client.users.delete(self.user['uuid'])

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
        url = 'https://{}:{}/0.1/backends'.format(self.auth_host, self.auth_port)
        response = requests.get(url, verify=False)
        backends = ['broken_init', 'broken_verify_password', 'wazo_user']
        assert_that(response.json()['data'], contains_inanyorder(*backends))

    def test_that_get_returns_the_auth_id(self):
        token = self._post_token('foo', 'bar')['token']

        response = self._get_token(token)

        assert_that(response['auth_id'], self.user['uuid'])

    def test_that_get_returns_the_xivo_uuid_in_the_response(self):
        token = self._post_token('foo', 'bar')['token']

        response = self._get_token(token)

        assert_that(
            response,
            has_entries(xivo_uuid='the-predefined-xivo-uuid'),
        )

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
        response = self._post_token('foo', 'bar')

        assert_that(
            response,
            has_entries(
                token=uuid_(),
                metadata=has_entries(uuid=self.user['uuid']),
                acls=ANY,
            ),
        )

    def test_that_an_unknown_type_returns_a_401(self):
        self._post_token_with_expected_exception('foo', 'not_bar', 'unexistant_backend', status_code=401)

    def test_that_a_broken_backend_returns_a_401(self):
        self._post_token_with_expected_exception('foo', 'not_bar', 'broken_verify_password', status_code=401)

    def test_that_no_type_returns_400(self):
        url = 'https://{}:{}/0.1/token'.format(self.auth_host, self.auth_port)
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

    def test_that_expired_tokens_do_not_leak_session_in_the_db(self):
        token_data = self._post_token('foo', 'bar')
        self.client.token.revoke(token_data['token'])

        until.false(self._is_session_in_the_db, token_data['session_uuid'], tries=5, interval=1)

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

    def test_that_unauthorized_tenants_on_HEAD_return_403(self):
        token = self._post_token('foo', 'bar')['token']

        assert_that(
            self._is_valid(token, tenant='55ee61f3-c4a5-427c-9f40-9d5c33466240'),
            is_(False),
        )

        assert_that(
            self._is_valid(token, tenant=self.top_tenant_uuid),
            is_(True),
        )

        with self.client_in_subtenant() as (_, __, sub_tenant):
            assert_that(
                self._is_valid(token, tenant=sub_tenant['uuid']),
                is_(True),
            )

    def test_that_unauthorized_acls_on_GET_return_403(self):
        token = self._post_token('foo', 'bar')['token']
        self._get_token_with_expected_exception(token, acls='confd', status_code=403)

    def test_that_unauthorized_tenants_on_GET_return_403(self):
        token = self._post_token('foo', 'bar')['token']

        self._get_token_with_expected_exception(
            token, tenant='55ee61f3-c4a5-427c-9f40-9d5c33466240', status_code=403)

        assert_that(
            calling(self.client.token.get).with_args(token),
            not_(raises(Exception)),
        )

        with self.client_in_subtenant() as (_, __, sub_tenant):
            assert_that(
                calling(self.client.token.get).with_args(token, tenant=sub_tenant['uuid']),
                not_(raises(Exception)),
            )

    @fixtures.http.policy(name='fooer', acl_templates=['foo'])
    def test_that_authorized_acls_on_HEAD_return_204(self, policy):
        self.client.users.add_policy(self.user['uuid'], policy['uuid'])

        token = self._post_token('foo', 'bar')['token']

        assert_that(self._is_valid(token, acls='foo'))

    @fixtures.http.policy(name='fooer', acl_templates=['foo'])
    def test_that_authorized_acls_on_GET_return_200(self, policy):
        self.client.users.add_policy(self.user['uuid'], policy['uuid'])

        token = self._post_token('foo', 'bar')['token']

        self._get_token(token, acls='foo')  # no exception

    def test_query_after_database_restart(self):
        token = self._post_token('foo', 'bar')['token']

        self.restart_postgres()

        token = self._post_token('foo', 'bar')['token']
        assert_that(self._is_valid(token))

    def _is_token_in_the_db(self, token):
        db_uri = os.getenv('DB_URI', 'postgresql://asterisk:proformatique@localhost:{port}')
        dao = TokenDAO(db_uri.format(port=self.service_port(5432, 'postgres')))
        try:
            dao.get(token)
            return True
        except exceptions.UnknownTokenException:
            return False

    def _is_session_in_the_db(self, session_uuid):
        db_uri = os.getenv('DB_URI', 'postgresql://asterisk:proformatique@localhost:{port}')
        dao = SessionDAO(db_uri.format(port=self.service_port(5432, 'postgres')))
        with dao.new_session() as s:
            result = s.query(models.Session).filter(models.Session.uuid == session_uuid).first()
        if result:
            return True
        return False


class TestNoSSLCertificate(AuthLaunchingTestCase):

    asset = 'no_ssl_certificate'

    def test_that_wazo_auth_stops_if_not_readable_ssl_certificate(self):
        self._assert_that_wazo_auth_is_stopping()

        log = self.service_logs('auth')
        assert_that(log, contains_string("No such file or directory: '/missing_server.crt'"))


class TestNoSSLKey(AuthLaunchingTestCase):

    asset = 'no_ssl_key'

    def test_that_wazo_auth_stops_if_not_readable_ssl_key(self):
        self._assert_that_wazo_auth_is_stopping()

        log = self.service_logs('auth')
        assert_that(log, contains_string("No such file or directory: '/missing_server.key'"))
