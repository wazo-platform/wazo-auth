# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import json
import os
import random
import requests
import string
import time
import unittest

from contextlib import contextmanager
from hamcrest import assert_that, calling, has_properties, equal_to
from xivo_test_helpers.hamcrest.raises import raises
from xivo_auth_client import Client
from xivo_test_helpers.asset_launching_test_case import AssetLaunchingTestCase
from xivo_test_helpers.bus import BusClient
from wazo_auth.database import queries
from wazo_auth.database.queries import group, policy, tenant, token, user

DB_URI = os.getenv('DB_URI', 'postgresql://asterisk:proformatique@localhost:{port}')
HOST = os.getenv('WAZO_AUTH_TEST_HOST', 'localhost')
UNKNOWN_UUID = '00000000-0000-0000-0000-000000000000'
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
    def _docker_compose_options(cls):
        return [
            '--file', os.path.join(cls.assets_root, 'docker-compose.yml'),
            '--file', os.path.join(cls.assets_root, 'docker-compose.{}.override.yml'.format(cls.asset)),
            '--project-name', cls.service,
        ]


class DAOTestCase(unittest.TestCase):

    unknown_uuid = '00000000-0000-0000-0000-000000000000'

    def setUp(self):
        db_uri = DB_URI.format(port=DBStarter.service_port(5432, 'postgres'))
        self._address_dao = queries.AddressDAO(db_uri)
        self._email_dao = queries.EmailDAO(db_uri)
        self._external_auth_dao = queries.ExternalAuthDAO(db_uri)
        self._group_dao = group.GroupDAO(db_uri)
        self._policy_dao = policy.PolicyDAO(db_uri)
        self._user_dao = user.UserDAO(db_uri)
        self._tenant_dao = tenant.TenantDAO(db_uri)
        self._token_dao = token.TokenDAO(db_uri)

        self.top_tenant_uuid = self._tenant_dao.find_top_tenant()


class AuthLaunchingTestCase(AssetLaunchingTestCase):

    assets_root = os.path.join(os.path.dirname(__file__), '../..', 'assets')
    service = 'auth'

    @classmethod
    def setUpClass(cls):
        cls.auth_host = HOST
        super(AuthLaunchingTestCase, cls).setUpClass()

    @classmethod
    def _docker_compose_options(cls):
        return [
            '--file', os.path.join(cls.assets_root, 'docker-compose.yml'),
            '--file', os.path.join(cls.assets_root, 'docker-compose.{}.override.yml'.format(cls.asset)),
            '--project-name', cls.service,
        ]

    def _assert_that_wazo_auth_is_stopping(self):
        for _ in range(5):
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
        super(BaseTestCase, cls).setUpClass()
        cls.auth_port = cls.service_port(9497, service_name='auth')

    def new_message_accumulator(self, routing_key):
        port = self.service_port(5672, service_name='rabbitmq')
        bus_client = BusClient.from_connection_fields(port=port, **self.bus_config)
        return bus_client.accumulator(routing_key)

    def get_emails(self):
        return [self._email_body(f) for f in self._get_email_filenames()]

    def _email_body(self, filename):
        return self.docker_exec(['cat', '{}/{}'.format(self.email_dir, filename)], 'smtp')

    def _get_email_filenames(self):
        return self.docker_exec(['ls', self.email_dir], 'smtp').strip().split('\n')

    def _post_token(self, username, password, backend=None, expiration=None):
        client = self.new_auth_client(username, password)
        backend = backend or 'wazo_user'
        args = {}
        if expiration:
            args['expiration'] = expiration
        return client.token.new(backend, **args)

    def _post_token_with_expected_exception(self, username, password, backend=None, expiration=None,
                                            status_code=None, msg=None):
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

    def _get_token_with_expected_exception(self, token, acls=None, tenant=None, status_code=None, msg=None):
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
        kwargs = {
            'port': cls.auth_port,
            'verify_certificate': False,
        }

        if username and password:
            kwargs['username'] = username
            kwargs['password'] = password

        return Client(cls.auth_host, **kwargs)


class WazoAuthTestCase(BaseTestCase):

    username = 'admin'
    password = 's3cre7'
    asset = 'base'

    @classmethod
    def setUpClass(cls):
        super(WazoAuthTestCase, cls).setUpClass()
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        url = 'https://{}:{}/0.1/init'.format(cls.auth_host, cls.auth_port)

        key = cls.docker_exec(['cat', '/var/lib/wazo-auth/init.key'])
        body = {'key': key, 'username': cls.username, 'password': cls.password}
        response = requests.post(url, data=json.dumps(body), headers=headers, verify=False)
        response.raise_for_status()

        cls.client = cls.new_auth_client(cls.username, cls.password)
        token_data = cls.client.token.new(backend='wazo_user', expiration=7200)
        cls.admin_user_uuid = token_data['metadata']['uuid']
        cls.client.set_token(token_data['token'])

        cls.top_tenant_uuid = cls.get_top_tenant()['uuid']

    @classmethod
    def get_top_tenant(cls):
        return cls.client.tenants.list(name='master')['items'][0]

    @contextmanager
    def policy(self, client, *args, **kwargs):
        policy = client.policies.new(*args, **kwargs)
        try:
            yield policy
        finally:
            try:
                client.policies.delete(policy['uuid'])
            except Exception:
                pass

    @contextmanager
    def tenant(self, client, *args, **kwargs):
        tenant = client.tenants.new(*args, **kwargs)
        try:
            yield tenant
        finally:
            try:
                client.tenants.delete(tenant['uuid'])
            except Exception:
                pass

    @contextmanager
    def user(self, client, register=False, *args, **kwargs):
        if register:
            user = client.users.register(*args, **kwargs)
        else:
            user = client.users.new(*args, **kwargs)

        try:
            yield user
        finally:
            try:
                client.users.delete(user['uuid'])
            except Exception:
                pass

    @contextmanager
    def client_in_subtenant(self, username=None, parent_uuid=None):
        random_string = lambda n: ''.join(random.choice(string.letters) for _ in range(n))
        username = username or random_string(8)
        password = 'secre7'
        tenant_args = {'name': 'mytenant'}
        if parent_uuid:
            tenant_args['parent_uuid'] = parent_uuid
        tenant = self.client.tenants.new(**tenant_args)
        user = self.client.users.new(username=username, password=password, tenant_uuid=tenant['uuid'])
        policy = self.client.policies.new(name=random_string(5), acl_templates=['auth.#'])
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


def assert_no_error(fn, *args, **kwargs):
    return fn(*args, **kwargs)


def assert_http_error(status_code, fn, *args, **kwargs):
    assert_that(
        calling(fn).with_args(*args, **kwargs),
        raises(requests.HTTPError).matching(
            has_properties('response', has_properties('status_code', status_code))))
