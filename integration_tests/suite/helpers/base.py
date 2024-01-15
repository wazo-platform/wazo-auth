# Copyright 2017-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import pytest
import random
import re
import requests
import string
import unittest

from datetime import datetime

from sqlalchemy.exc import UnboundExecutionError
from contextlib import contextmanager
from hamcrest import (
    assert_that,
    calling,
    contains_exactly,
    equal_to,
    greater_than,
    has_length,
    has_properties,
)
from kombu import Exchange
from wazo_auth_client import Client
from wazo_test_helpers import until
from wazo_test_helpers.hamcrest.raises import raises
from wazo_test_helpers.asset_launching_test_case import (
    AssetLaunchingTestCase,
    NoSuchPort,
    NoSuchService,
    WrongClient,
)
from wazo_test_helpers.bus import BusClient
from wazo_auth.database import queries, helpers
from wazo_auth.database.queries import (
    group,
    ldap_config,
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

use_asset = pytest.mark.usefixtures


class BaseAssetLaunchingTestCase(AssetLaunchingTestCase):
    assets_root = os.path.join(os.path.dirname(__file__), '../..', 'assets')
    service = 'auth'
    auth_host = '127.0.0.1'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        port = cls.service_port(5432, 'postgres')
        db_uri = DB_URI.format(port=port)
        helpers.init_db(db_uri)

    @classmethod
    def tearDownClass(cls):
        try:
            helpers.deinit_db()
        except UnboundExecutionError:
            pass
        super().tearDownClass()

    @classmethod
    def make_auth_client(cls, username=None, password=None):
        try:
            port = cls.service_port(9497, service_name='auth')
        except (NoSuchService, NoSuchPort):
            return WrongClient('auth')
        kwargs = {'port': port, 'prefix': '', 'https': False}

        if username and password:
            kwargs['username'] = username
            kwargs['password'] = password

        return Client(cls.auth_host, **kwargs)

    @classmethod
    def make_db_client(cls):
        try:
            port = cls.service_port(5432, 'postgres')
        except (NoSuchService, NoSuchPort):
            return WrongClient('postgres')
        db_uri = DB_URI.format(port=port)
        return Database(db_uri, db='asterisk')

    @classmethod
    def make_bus_client(cls):
        try:
            port = cls.service_port(5672, 'rabbitmq')
        except (NoSuchService, NoSuchPort):
            return WrongClient('rabbitmq')
        upstream = Exchange('xivo', 'topic')
        bus = BusClient.from_connection_fields(
            host='127.0.0.1',
            port=port,
            exchange_name='wazo-headers',
            exchange_type='headers',
        )
        bus.downstream_exchange_declare('wazo-headers', 'headers', upstream)
        return bus

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
        auth = cls.make_auth_client()
        logging.getLogger('wazo_test_helpers').setLevel(logging.INFO)
        until.return_(auth.status.check, timeout=30)
        logging.getLogger('wazo_test_helpers').setLevel(logging.DEBUG)


class DBAssetLaunchingTestCase(BaseAssetLaunchingTestCase):
    asset = 'database'
    service = 'postgres'


class APIAssetLaunchingTestCase(BaseAssetLaunchingTestCase):
    asset = 'base'


class ExternalAuthAssetLaunchingTestCase(BaseAssetLaunchingTestCase):
    asset = 'external_auth'


class MetadataAssetLaunchingTestCase(BaseAssetLaunchingTestCase):
    asset = 'metadata'


class DAOTestCase(unittest.TestCase):
    unknown_uuid = '00000000-0000-0000-0000-000000000000'

    def setUp(self):
        self.Session = helpers.Session
        self._address_dao = queries.AddressDAO()
        self._email_dao = queries.EmailDAO()
        self._external_auth_dao = queries.ExternalAuthDAO()
        self._group_dao = group.GroupDAO()
        self._ldap_config_dao = ldap_config.LDAPConfigDAO()
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

    @contextmanager
    def check_db_requests(self, nb_requests):
        time_start = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        nb_logs_start = DBAssetLaunchingTestCase.count_database_logs(since=time_start)
        yield
        nb_logs_end = DBAssetLaunchingTestCase.count_database_logs(since=time_start)
        nb_db_requests = nb_logs_end - nb_logs_start
        assert_that(nb_db_requests, equal_to(nb_requests))


class BaseIntegrationTest(unittest.TestCase):
    @classmethod
    def make_auth_client(cls, *args, **kwargs):
        return cls.asset_cls.make_auth_client(*args, **kwargs)

    def _post_token(self, username, password, *args, **kwargs):
        auth = self.asset_cls.make_auth_client(username, password)
        return auth.token.new(*args, **kwargs)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.reset_clients()
        cls.top_tenant_uuid = cls.get_top_tenant()['uuid']

    @classmethod
    def reset_clients(cls):
        cls.client = cls.asset_cls.make_auth_client(cls.username, cls.password)
        token = cls.client.token.new(expiration=7200)
        cls.client.set_token(token['token'])
        cls.admin_token = token['token']
        cls.admin_user_uuid = token['metadata']['uuid']
        cls.bus = cls.asset_cls.make_bus_client()
        cls.database = cls.asset_cls.make_db_client()

    @property
    def auth_host(self):
        return self.asset_cls.auth_host

    @property
    def auth_port(self):
        return self.asset_cls.service_port(9497, 'auth')

    @property
    def oauth2_port(self):
        return self.asset_cls.service_port(80, 'oauth2sync')

    @classmethod
    def restart_auth(cls):
        cls.asset_cls.restart_auth()
        cls.reset_clients()

    @classmethod
    def restart_postgres(cls):
        return cls.asset_cls.restart_postgres()

    @classmethod
    def service_logs(cls, *args, **kwargs):
        return cls.asset_cls.service_logs(*args, **kwargs)

    @classmethod
    def stop_service(cls, *args, **kwargs):
        return cls.asset_cls.stop_service(*args, **kwargs)

    @classmethod
    def start_service(cls, *args, **kwargs):
        return cls.asset_cls.start_service(*args, **kwargs)

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
        client = self.asset_cls.make_auth_client(username, password)
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


class ExternalAuthIntegrationTest(BaseIntegrationTest):
    asset_cls = ExternalAuthAssetLaunchingTestCase
    username = 'admin'
    password = 's3cre7'


class MetadataIntegrationTest(BaseIntegrationTest):
    asset_cls = MetadataAssetLaunchingTestCase
    username = 'admin'
    password = 's3cre7'


class APIIntegrationTest(BaseIntegrationTest):
    asset_cls = APIAssetLaunchingTestCase
    username = 'admin'
    password = 's3cre7'

    def assert_last_email(
        self,
        from_name,
        from_address,
        to_name,
        to_address,
        body_contains=None,
    ):
        assert (
            self.get_last_email_from() == f'{from_name} <{from_address}>'
        ), self.get_last_email_from()
        assert (
            self.get_last_email_to() == f'{to_name} <{to_address}>'
        ), self.get_last_email_to()
        if body_contains:
            assert re.search(
                body_contains, self.get_last_email_body(), re.MULTILINE
            ), self.get_last_email_body()

    def get_last_email_url(self):
        last_email = self.get_emails()[-1]
        email_urls = [
            line for line in last_email.split('\n') if line.startswith('https://')
        ]
        return email_urls[-1]

    def get_last_email_from(self):
        last_email = self.get_emails()[-1]
        email_froms = [
            line for line in last_email.split('\n') if line.startswith('From: ')
        ]
        return email_froms[-1][6:]

    def get_last_email_to(self):
        last_email = self.get_emails()[-1]
        email_froms = [
            line for line in last_email.split('\n') if line.startswith('To: ')
        ]
        return email_froms[-1][4:]

    def get_last_email_body(self):
        last_email = self.get_emails()[-1]
        headers, body = last_email.split('\n\n', 1)
        return body

    def get_emails(self):
        return [self._email_body(f) for f in self._get_email_filenames()]

    def _email_body(self, filename):
        command = ['cat', f'/var/mail/{filename}']
        return self.asset_cls.docker_exec(command, 'smtp').decode('utf-8')

    def _get_email_filenames(self):
        command = ['ls', '/var/mail']
        return (
            self.asset_cls.docker_exec(command, 'smtp')
            .decode('utf-8')
            .strip()
            .split('\n')
        )

    def clean_emails(self):
        for filename in self._get_email_filenames():
            self._remove_email(filename)

    def _remove_email(self, filename):
        command = ['rm', f'/var/mail/{filename}']
        self.asset_cls.docker_exec(command, 'smtp')

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


def assert_http_error(status_code, http_fn, *args, **kwargs):
    assert_that(
        calling(http_fn).with_args(*args, **kwargs),
        raises(requests.HTTPError).matching(
            has_properties('response', has_properties('status_code', status_code))
        ),
    )


def assert_sorted(http_fn, order, expected):
    asc_items = http_fn(order=order, direction='asc')['items']
    desc_items = http_fn(order=order, direction='desc')['items']

    assert_that(
        asc_items, has_length(greater_than(1)), 'sorting requires at least 2 items'
    )
    assert_that(asc_items, contains_exactly(*expected))
    assert_that(desc_items, contains_exactly(*reversed(expected)))
