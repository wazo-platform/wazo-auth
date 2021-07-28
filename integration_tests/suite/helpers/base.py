# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import random
import requests
import string
import unittest

from contextlib import contextmanager
from hamcrest import (
    assert_that,
    calling,
    contains,
    greater_than,
    has_length,
    has_properties,
)
from wazo_auth_client import Client
from xivo_test_helpers import until
from xivo_test_helpers.hamcrest.raises import raises
from xivo_test_helpers.asset_launching_test_case import AssetLaunchingTestCase
from xivo_test_helpers.bus import BusClient
from wazo_auth import bootstrap
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

logging.getLogger('wazo_auth').setLevel(logging.WARNING)

SUB_TENANT_UUID = '76502c2b-cce5-409c-ab8f-d1fe41141a2d'
ADDRESS_NULL = {
    'line_1': None,
    'line_2': None,
    'city': None,
    'state': None,
    'country': None,
    'zip_code': None,
}


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
        self.Session = helpers.Session
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
        self._remove_unrelated_default_autocreate_objects()

        self.session.begin_nested()

    def tearDown(self):
        self.session.rollback()
        helpers.Session.remove()

    def _remove_unrelated_default_autocreate_objects(self):
        for item in self._group_dao.list_():
            self._group_dao.delete(item['uuid'])

    @property
    def session(self):
        return helpers.get_db_session()


class BaseTestCase(AssetLaunchingTestCase):

    assets_root = os.path.join(os.path.dirname(__file__), '../..', 'assets')
    service = 'auth'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.auth_host = '127.0.0.1'
        cls.auth_port = cls.service_port(9497, service_name='auth')

    def new_message_accumulator(self, routing_key):
        bus_client = self.make_bus_client()
        return bus_client.accumulator(routing_key)

    def get_last_email_url(self):
        last_email = self.get_emails()[-1]
        email_urls = [
            line for line in last_email.split('\n') if line.startswith('https://')
        ]
        return email_urls[-1]

    def get_emails(self):
        return [self._email_body(f) for f in self._get_email_filenames()]

    def _email_body(self, filename):
        command = ['cat', f'/var/mail/{filename}']
        return self.docker_exec(command, 'smtp').decode('utf-8')

    def _get_email_filenames(self):
        command = ['ls', '/var/mail']
        return self.docker_exec(command, 'smtp').decode('utf-8').strip().split('\n')

    def _post_token(self, username, password, *args, **kwargs):
        client = self.make_auth_client(username, password)
        return client.token.new(*args, **kwargs)

    @classmethod
    def make_auth_client(cls, username=None, password=None):
        port = cls.auth_port
        kwargs = {'port': port, 'prefix': '', 'https': False}

        if username and password:
            kwargs['username'] = username
            kwargs['password'] = password

        return Client(cls.auth_host, **kwargs)

    @classmethod
    def make_db_client(cls):
        port = cls.service_port(5432, 'postgres')
        db_uri = DB_URI.format(port=port)
        return Database(db_uri, db='asterisk')

    @classmethod
    def make_bus_client(cls):
        port = cls.service_port(5672, 'rabbitmq')
        return BusClient.from_connection_fields(host='127.0.0.1', port=port)

    @classmethod
    def restart_postgres(cls):
        cls.restart_service('postgres')
        database = cls.make_db_client()
        until.true(database.is_up, timeout=5, message='Postgres did not come back up')
        helpers.deinit_db()
        helpers.init_db(database.uri)

    @classmethod
    def restart_auth(cls):
        cls.restart_service('auth')
        cls.auth_port = cls.service_port(9497, service_name='auth')
        auth = cls.make_auth_client(cls.username, cls.password)
        until.return_(auth.status.check, timeout=30)


class WazoAuthTestCase(BaseTestCase):

    username = 'admin'
    password = 's3cre7'
    asset = 'base'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        database = cls.make_db_client()
        helpers.init_db(database.uri)

        cls.reset_clients()

        policies = cls.client.policies.list(slug=bootstrap.DEFAULT_POLICY_SLUG)
        policy = policies['items'][0]
        new_acl = policy.pop('acl') + ['!unauthorized']
        cls.client.policies.edit(policy['uuid'], acl=new_acl, **policy)

        token_data = cls.client.token.new(backend='wazo_user', expiration=7200)
        cls.admin_user_uuid = token_data['metadata']['uuid']
        cls.client.set_token(token_data['token'])

        cls.top_tenant_uuid = cls.get_top_tenant()['uuid']

    @classmethod
    def tearDownClass(cls):
        helpers.deinit_db()
        super().tearDownClass()

    @classmethod
    def reset_clients(cls):
        cls.client = cls.make_auth_client(cls.username, cls.password)
        token = cls.client.token.new(expiration=7200)['token']
        cls.client.set_token(token)
        cls.admin_token = token

    @classmethod
    def get_top_tenant(cls):
        return cls.client.tenants.list(name='master')['items'][0]

    @contextmanager
    def client_in_subtenant(self, username=None, parent_uuid=None):
        def random_string(n):
            return ''.join(random.choice(string.ascii_letters) for _ in range(n))

        username = username or random_string(8)
        password = 'secre7'
        tenant_args = {'name': 'mytenant', 'slug': random_string(10)}
        if parent_uuid:
            tenant_args['parent_uuid'] = parent_uuid
        tenant = self.client.tenants.new(**tenant_args)
        user = self.client.users.new(
            username=username, password=password, tenant_uuid=tenant['uuid']
        )
        policy = self.client.policies.new(name=random_string(5), acl=['#'])
        self.client.users.add_policy(user['uuid'], policy['uuid'])
        client = self.make_auth_client(username, password)
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


def assert_no_error(fn, *args, **kwargs):
    return fn(*args, **kwargs)


def assert_http_error(status_code, fn, *args, **kwargs):
    assert_that(
        calling(fn).with_args(*args, **kwargs),
        raises(requests.HTTPError).matching(
            has_properties('response', has_properties('status_code', status_code))
        ),
    )


def assert_sorted(action, order, expected):
    asc_items = action(order=order, direction='asc')['items']
    desc_items = action(order=order, direction='desc')['items']

    assert_that(
        asc_items, has_length(greater_than(1)), 'sorting requires atleast 2 items'
    )
    assert_that(asc_items, contains(*expected))
    assert_that(desc_items, contains(*reversed(expected)))
