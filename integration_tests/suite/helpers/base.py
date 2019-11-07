# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import random
import requests
import string
import time
import unittest

from contextlib import contextmanager
from hamcrest import (
    assert_that,
    calling,
    contains,
    greater_than,
    has_length,
    has_properties,
    equal_to,
)
from wazo_auth_client import Client
from xivo_test_helpers import until
from xivo_test_helpers.hamcrest.raises import raises
from xivo_test_helpers.asset_launching_test_case import AssetLaunchingTestCase
from xivo_test_helpers.bus import BusClient
from wazo_auth.database import queries, helpers
from wazo_auth.database.queries import (
    group,
    policy,
    tenant,
    token,
    user,
    refresh_token,
    session,
)

from .constants import DB_URI
from .database import Database

HOST = os.getenv('WAZO_AUTH_TEST_HOST', 'localhost')
SUB_TENANT_UUID = '76502c2b-cce5-409c-ab8f-d1fe41141a2d'
ADDRESS_NULL = {
    'line_1': None,
    'line_2': None,
    'city': None,
    'state': None,
    'country': None,
    'zip_code': None,
}


def assert_sorted(action, order, expected):
    asc_items = action(order=order, direction='asc')['items']
    desc_items = action(order=order, direction='desc')['items']

    assert_that(
        asc_items, has_length(greater_than(1)), 'sorting requires atleast 2 items'
    )
    assert_that(asc_items, contains(*expected))
    assert_that(desc_items, contains(*reversed(expected)))


class DBStarter(AssetLaunchingTestCase):

    asset = 'database'
    assets_root = os.path.join(os.path.dirname(__file__), '../..', 'assets')
    service = 'postgres'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.db_uri = DB_URI.format(port=DBStarter.service_port(5432, 'postgres'))
        helpers.init_db(cls.db_uri)

    @classmethod
    def tearDownClass(cls):
        helpers.deinit_db()
        super().tearDownClass()


class DAOTestCase(unittest.TestCase):

    unknown_uuid = '00000000-0000-0000-0000-000000000000'

    def setUp(self):
        self._address_dao = queries.AddressDAO()
        self._email_dao = queries.EmailDAO()
        self._external_auth_dao = queries.ExternalAuthDAO()
        self._group_dao = group.GroupDAO()
        self._policy_dao = policy.PolicyDAO()
        self._user_dao = user.UserDAO()
        self._refresh_token_dao = refresh_token.RefreshTokenDAO()
        self._tenant_dao = tenant.TenantDAO()
        self._token_dao = token.TokenDAO()
        self._session_dao = session.SessionDAO()

        self.top_tenant_uuid = self._tenant_dao.find_top_tenant()


class AuthLaunchingTestCase(AssetLaunchingTestCase):

    assets_root = os.path.join(os.path.dirname(__file__), '../..', 'assets')
    service = 'auth'

    @classmethod
    def setUpClass(cls):
        cls.auth_host = HOST
        super().setUpClass()

    def _assert_that_wazo_auth_is_stopping(self):
        for _ in range(20):
            if not self.service_status('auth')['State']['Running']:
                break
            time.sleep(0.2)
        else:
            self.fail('wazo-auth did not stop')


class BaseTestCase(AuthLaunchingTestCase):

    bus_config = {'user': 'guest', 'password': 'guest', 'host': 'localhost'}
    email_dir = '/var/mail'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.auth_port = cls.service_port(9497, service_name='auth')

    def new_message_accumulator(self, routing_key):
        port = self.service_port(5672, service_name='rabbitmq')
        bus_client = BusClient.from_connection_fields(port=port, **self.bus_config)
        return bus_client.accumulator(routing_key)

    def get_emails(self):
        return [self._email_body(f) for f in self._get_email_filenames()]

    def _email_body(self, filename):
        return self.docker_exec(
            ['cat', '{}/{}'.format(self.email_dir, filename)], 'smtp'
        ).decode('utf-8')

    def _get_email_filenames(self):
        return (
            self.docker_exec(['ls', self.email_dir], 'smtp')
            .decode('utf-8')
            .strip()
            .split('\n')
        )

    def _post_token(
        self, username, password, backend=None, expiration=None, session_type=None
    ):
        client = self.new_auth_client(username, password)
        args = {}
        if backend:
            args['backend'] = backend
        if expiration:
            args['expiration'] = expiration
        if session_type:
            args['session_type'] = session_type
        return client.token.new(**args)

    def _post_token_with_expected_exception(
        self,
        username,
        password,
        backend=None,
        expiration=None,
        status_code=None,
        msg=None,
    ):
        try:
            self._post_token(username, password, backend, expiration)
        except requests.HTTPError as e:
            if status_code:
                assert_that(e.response.status_code, equal_to(status_code))
            if msg:
                assert_that(e.response.json()['reason'][0], equal_to(msg))
        else:
            self.fail('Should have raised an exception')

    def _get_token(self, token, acls=None, tenant=None):
        client = self.new_auth_client()
        args = {}
        if acls:
            args['required_acl'] = acls
        if tenant:
            args['tenant'] = tenant

        return client.token.get(token, **args)

    def _get_token_with_expected_exception(
        self, token, acls=None, tenant=None, status_code=None, msg=None
    ):
        try:
            self._get_token(token, acls, tenant)
        except requests.HTTPError as e:
            if status_code:
                assert_that(e.response.status_code, equal_to(status_code))
            if msg:
                assert_that(e.response.json()['reason'][0], equal_to(msg))
        else:
            self.fail('Should have raised an exception')

    def _delete_token(self, token):
        client = self.new_auth_client()
        return client.token.revoke(token)

    def _is_valid(self, token, acls=None, tenant=None):
        client = self.new_auth_client()
        args = {}
        if acls:
            args['required_acl'] = acls
        return client.token.is_valid(token, tenant=tenant, **args)

    @classmethod
    def new_auth_client(cls, username=None, password=None):
        kwargs = {'port': cls.auth_port, 'verify_certificate': False}

        if username and password:
            kwargs['username'] = username
            kwargs['password'] = password

        return Client(cls.auth_host, **kwargs)

    @classmethod
    def new_db_client(cls):
        db_uri = DB_URI.format(port=cls.service_port(5432, 'postgres'))
        return Database(db_uri, db='asterisk')

    def restart_postgres(self):
        self.restart_service('postgres')
        database = self.new_db_client()
        until.true(database.is_up, timeout=5, message='Postgres did not come back up')
        helpers.deinit_db()
        helpers.init_db(database.uri)


class WazoAuthTestCase(BaseTestCase):

    username = 'admin'
    password = 's3cre7'
    asset = 'base'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        url = 'https://{}:{}/0.1/init'.format(cls.auth_host, cls.auth_port)

        key = cls.docker_exec(['cat', '/var/lib/wazo-auth/init.key']).decode('utf-8')
        body = {'key': key, 'username': cls.username, 'password': cls.password}
        response = requests.post(url, json=body, headers=headers, verify=False)
        response.raise_for_status()

        cls.client = cls.new_auth_client(cls.username, cls.password)
        token_data = cls.client.token.new(backend='wazo_user', expiration=7200)
        cls.admin_user_uuid = token_data['metadata']['uuid']
        cls.admin_token = token_data['token']
        cls.client.set_token(token_data['token'])

        cls.top_tenant_uuid = cls.get_top_tenant()['uuid']

    @classmethod
    def get_top_tenant(cls):
        return cls.client.tenants.list(name='master')['items'][0]

    @contextmanager
    def client_in_subtenant(self, username=None, parent_uuid=None):
        def random_string(n):
            return ''.join(random.choice(string.ascii_letters) for _ in range(n))

        username = username or random_string(8)
        password = 'secre7'
        tenant_args = {'name': 'mytenant'}
        if parent_uuid:
            tenant_args['parent_uuid'] = parent_uuid
        tenant = self.client.tenants.new(**tenant_args)
        user = self.client.users.new(
            username=username, password=password, tenant_uuid=tenant['uuid']
        )
        policy = self.client.policies.new(
            name=random_string(5), acl_templates=['auth.#']
        )
        self.client.users.add_policy(user['uuid'], policy['uuid'])
        client = self.new_auth_client(username, password)
        token = client.token.new(backend='wazo_user', expiration=3600)['token']
        client.set_token(token)

        try:
            yield client, user, tenant
        finally:
            self.client.token.revoke(token)
            try:
                self.client.tenants.delete(tenant['uuid'])
            except Exception:
                pass
            self.client.policies.delete(policy['uuid'])

    @staticmethod
    @contextmanager
    def group(client, *args, **kwargs):
        create = client.groups.new
        delete = client.groups.delete

        with _resource(create, delete, *args, **kwargs) as group:
            yield group

    @staticmethod
    @contextmanager
    def policy(client, *args, **kwargs):
        create = client.policies.new
        delete = client.policies.delete

        with _resource(create, delete, *args, **kwargs) as policy:
            yield policy

    @staticmethod
    @contextmanager
    def tenant(client, *args, **kwargs):
        create = client.tenants.new
        delete = client.tenants.delete

        with _resource(create, delete, *args, **kwargs) as tenant:
            yield tenant

    @staticmethod
    @contextmanager
    def user(client, register=False, *args, **kwargs):
        if register:
            create = client.users.register
        else:
            create = client.users.new
        delete = client.users.delete

        with _resource(create, delete, *args, **kwargs) as user:
            yield user


def assert_no_error(fn, *args, **kwargs):
    return fn(*args, **kwargs)


def assert_http_error(status_code, fn, *args, **kwargs):
    assert_that(
        calling(fn).with_args(*args, **kwargs),
        raises(requests.HTTPError).matching(
            has_properties('response', has_properties('status_code', status_code))
        ),
    )


@contextmanager
def _resource(create, delete, *args, **kwargs):
    resource = create(*args, **kwargs)
    try:
        yield resource
    finally:
        try:
            delete(resource['uuid'])
        except Exception:
            pass
