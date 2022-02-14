# Copyright 2015-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time
import uuid
import logging

from datetime import datetime, timedelta

import requests
from mock import ANY
from hamcrest import (
    assert_that,
    calling,
    contains_inanyorder,
    empty,
    equal_to,
    has_entries,
    has_key,
    is_,
    not_,
    raises,
)

from wazo_test_helpers import until
from wazo_test_helpers.hamcrest.uuid_ import uuid_
from wazo_auth.database import helpers
from wazo_auth.database import models
from .helpers import fixtures, base
from .helpers.constants import UNKNOWN_TENANT, ISO_DATETIME

requests.packages.urllib3.disable_warnings()
logger = logging.getLogger(__name__)


def _new_token_id():
    return uuid.uuid4()


@base.use_asset('base')
class TestCore(base.APIIntegrationTest):
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

        assert_that(self.client.token.is_valid(token))

    def test_that_head_with_an_invalid_token_returns_404(self):
        assert_that(self.client.token.is_valid('abcdef'), is_(False))

    def test_backends(self):
        url = 'http://{}:{}/0.1/backends'.format(self.auth_host, self.auth_port)
        response = requests.get(url, verify=False)
        backends = ['broken_init', 'broken_verify_password', 'wazo_user', 'ldap_user']
        assert_that(response.json()['data'], contains_inanyorder(*backends))

    def test_that_get_returns_the_auth_id(self):
        token = self._post_token('foo', 'bar')['token']

        response = self.client.token.get(token)

        assert_that(response['auth_id'], self.user['uuid'])

    def test_that_get_returns_the_xivo_uuid_in_the_response(self):
        token = self._post_token('foo', 'bar')['token']

        response = self.client.token.get(token)

        assert_that(response, has_entries(xivo_uuid='the-predefined-xivo-uuid'))

    def test_that_get_returns_the_pbx_user_uuid(self):
        token = self._post_token('foo', 'bar')['token']

        response = self.client.token.get(token)

        assert_that(response, has_entries(metadata=has_key('pbx_user_uuid')))
        assert_that(response, has_key('xivo_user_uuid'))  # Compatibility

    def test_that_get_does_not_work_after_delete(self):
        token = self._post_token('foo', 'bar')['token']
        self.client.token.revoke(token)
        assert_that(
            calling(self.client.token.get).with_args(token),
            raises(requests.HTTPError, pattern='404'),
        )

    def test_that_deleting_unexistant_token_returns_200(self):
        self.client.token.revoke(_new_token_id())

    def test_that_the_wrong_password_returns_401(self):
        assert_that(
            calling(self._post_token).with_args('foo', 'not_bar'),
            raises(requests.HTTPError, pattern='401'),
        )

    def test_that_the_right_credentials_return_a_token_with_datas(self):
        response = self._post_token('foo', 'bar')

        assert_that(
            response,
            has_entries(
                token=uuid_(),
                metadata=has_entries(uuid=self.user['uuid']),
                acl=ANY,
            ),
        )

    def test_that_an_unknown_type_returns_a_401(self):
        args = ('foo', 'not_bar', 'unexistant_backend')
        assert_that(
            calling(self._post_token).with_args(*args),
            raises(requests.HTTPError, pattern='401'),
        )

    def test_that_a_broken_backend_returns_a_401(self):
        args = ('foo', 'not_bar', 'broken_verify_password')
        assert_that(
            calling(self._post_token).with_args(*args),
            raises(requests.HTTPError, pattern='401'),
        )

    def test_that_no_type_returns_400(self):
        url = 'http://{}:{}/0.1/token'.format(self.auth_host, self.auth_port)
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
        utc_expiration_time = datetime.strptime(
            token_data['utc_expires_at'], ISO_DATETIME
        )

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

        until.false(
            self._is_session_in_the_db, token_data['session_uuid'], tries=5, interval=1
        )

    def test_the_expiration_argument_as_a_string(self):
        assert_that(
            calling(self._post_token).with_args('foo', 'bar', expiration="string"),
            raises(requests.HTTPError, pattern='400'),
        )

    def test_negative_expiration(self):
        assert_that(
            calling(self._post_token).with_args('foo', 'bar', expiration=-1),
            raises(requests.HTTPError, pattern='400'),
        )

    def test_that_expired_tokens_are_not_valid(self):
        token = self._post_token('foo', 'bar', expiration=1)['token']

        time.sleep(2)

        assert_that(self.client.token.is_valid(token), equal_to(False))

    def test_that_invalid_unicode_access_returns_403(self):
        token = self._post_token('foo', 'bar')['token']
        assert_that(self.client.token.is_valid(token, required_acl='éric'), is_(False))

    def test_that_unauthorized_access_on_HEAD_return_403(self):
        token = self._post_token('foo', 'bar')['token']
        assert_that(self.client.token.is_valid(token, required_acl='confd'), is_(False))

    def test_that_unauthorized_tenants_on_HEAD_return_403(self):
        token = self._post_token('foo', 'bar')['token']

        assert_that(
            self.client.token.is_valid(token, tenant=UNKNOWN_TENANT),
            is_(False),
        )

        assert_that(
            self.client.token.is_valid(token, tenant=self.top_tenant_uuid),
            is_(True),
        )

        with self.client_in_subtenant() as (sub_client, __, sub_tenant):
            assert_that(
                self.client.token.is_valid(token, tenant=sub_tenant['uuid']),
                is_(True),
            )
            assert_that(
                self.client.token.is_valid(
                    sub_client._token_id, tenant=self.top_tenant_uuid
                ),
                is_(False),
            )

    def test_that_unauthorized_access_on_GET_return_403(self):
        token = self._post_token('foo', 'bar')['token']
        assert_that(
            calling(self.client.token.get).with_args(token, required_acl='confd'),
            raises(requests.HTTPError, pattern='403'),
        )

    def test_that_unauthorized_tenants_on_GET_return_403(self):
        token = self._post_token('foo', 'bar')['token']

        assert_that(
            calling(self.client.token.get).with_args(token, tenant=UNKNOWN_TENANT),
            raises(requests.HTTPError, pattern='403'),
        )

        assert_that(
            calling(self.client.token.get).with_args(token), not_(raises(Exception))
        )

        with self.client_in_subtenant() as (_, __, sub_tenant):
            assert_that(
                calling(self.client.token.get).with_args(
                    token, tenant=sub_tenant['uuid']
                ),
                not_(raises(Exception)),
            )

    @fixtures.http.policy(name='fooer', acl=['foo'])
    def test_that_authorized_access_on_HEAD_return_204(self, policy):
        self.client.users.add_policy(self.user['uuid'], policy['uuid'])

        token = self._post_token('foo', 'bar')['token']

        assert_that(self.client.token.is_valid(token, required_acl='foo'))

    @fixtures.http.policy(name='fooer', acl=['foo'])
    def test_that_authorized_access_on_GET_return_200(self, policy):
        self.client.users.add_policy(self.user['uuid'], policy['uuid'])

        token = self._post_token('foo', 'bar')['token']

        self.client.token.get(token, required_acl='foo')  # no exception

    def test_that_expired_tokens_on_scope_check_returns_404(self):
        token = self._post_token('foo', 'bar', expiration=1)['token']

        time.sleep(2)

        assert_that(
            calling(self.client.token.check_scopes).with_args(token, ['foo']),
            raises(requests.HTTPError, pattern='404'),
        )

    def test_that_scope_check_with_an_invalid_token_returns_404(self):
        assert_that(
            calling(self.client.token.check_scopes).with_args('abcdef', []),
            raises(requests.HTTPError, pattern='404'),
        )

    def test_that_unauthorized_acl_on_scope_check_return_all_false(self):
        token = self._post_token('foo', 'bar')['token']
        assert_that(
            self.client.token.check_scopes(token, ['confd', 'foo', 'bar'])['scopes'],
            has_entries(confd=False, foo=False, bar=False),
        )

    def test_that_unauthorized_tenants_on_scope_check_return_403(self):
        token = self._post_token('foo', 'bar')['token']

        assert_that(
            calling(self.client.token.check_scopes).with_args(
                token, ['foo'], tenant=UNKNOWN_TENANT
            ),
            raises(requests.HTTPError, pattern='403'),
        )

        assert_that(
            calling(self.client.token.check_scopes).with_args(
                token, ['foo'], tenant=self.top_tenant_uuid
            ),
            not_(raises(Exception)),
        )

        with self.client_in_subtenant() as (sub_client, __, sub_tenant):
            assert_that(
                calling(self.client.token.check_scopes).with_args(
                    token, ['foo'], tenant=sub_tenant['uuid']
                ),
                not_(raises(Exception)),
            )
            assert_that(
                calling(self.client.token.check_scopes).with_args(
                    sub_client._token_id, ['foo'], tenant=self.top_tenant_uuid
                ),
                raises(requests.HTTPError, pattern='403'),
            )

    @fixtures.http.policy(name='fooer', acl=['foo'])
    def test_that_authorized_acl_on_scope_check_returns_only_valid_accesses(
        self, policy
    ):
        self.client.users.add_policy(self.user['uuid'], policy['uuid'])

        token = self._post_token('foo', 'bar')['token']

        assert_that(
            self.client.token.check_scopes(token, ['foo', 'bar'])['scopes'],
            has_entries(foo=True, bar=False),
        )

    def test_that_no_acl_on_scope_check_returns_empty_result(self):
        token = self._post_token('foo', 'bar')['token']

        assert_that(self.client.token.check_scopes(token, [])['scopes'], is_(empty()))

    def test_that_wrong_type_acl_on_scope_check_raises_400(self):
        token = self._post_token('foo', 'bar')['token']

        assert_that(
            calling(self.client.token.check_scopes).with_args(token, [True]),
            raises(requests.HTTPError, pattern='400'),
        )

    def test_query_after_database_restart(self):
        token = self._post_token('foo', 'bar')['token']

        self.restart_postgres()
        self.reset_clients()

        token = self._post_token('foo', 'bar')['token']
        assert_that(self.client.token.is_valid(token))

    def _is_token_in_the_db(self, token):
        s = helpers.get_db_session()
        result = s.query(models.Token).filter(models.Token.uuid == token).first()
        return True if result else False

    def _is_session_in_the_db(self, session_uuid):
        s = helpers.get_db_session()
        result = (
            s.query(models.Session).filter(models.Session.uuid == session_uuid).first()
        )
        return True if result else False
