# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Avencall
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

import json
import logging
import requests
import subprocess
import unittest
import time
import os
import uuid

from contextlib import contextmanager
from datetime import datetime
from hamcrest import assert_that
from hamcrest import contains_inanyorder
from hamcrest import contains_string
from hamcrest import empty
from hamcrest import equal_to
from hamcrest import has_key
from hamcrest import has_length
from hamcrest import is_
from hamcrest import less_than
from hamcrest.core.base_matcher import BaseMatcher

requests.packages.urllib3.disable_warnings()
logger = logging.getLogger(__name__)

ISO_DATETIME = '%Y-%m-%dT%H:%M:%S.%f'

HOST = os.getenv('XIVO_AUTH_TEST_HOST', 'localhost')


def _new_token_id():
    return uuid.uuid4()


class HTTPErrorMatcher(BaseMatcher):

    def __init__(self, code, msg):
        self._code = code
        self._msg = msg
        self._description = None

    def _matches(self, item):
        data = item.json()

        for key in ['status_code', 'timestamp', 'reason']:
            if key not in data:
                self._description = 'error should have a key {}'.format(key)
                return False

        if self._code != item.status_code or self._code != data['status_code']:
            self._description = 'expected status code is {}, got {} and {} in the body'.format(
                self._code, item.status_code, data['status_code'])
            return False

        assert_that(data['reason'], contains_inanyorder(self._msg),
                    'Error message should be {}'.format(self._msg))
        return True

    def describe_to(self, description):
        if self._description:
            description.append_text(self._description)


def http_error(code, msg):
    return HTTPErrorMatcher(code, msg)


class AssetRunner(object):

    _launcher = 'docker-compose'
    _instance = None

    def __init__(self):
        self._running_asset = None

    def __del__(self):
        self.stop()

    def is_running(self, service):
        service_id = self._get_service_id(service)
        status = self._run_cmd('docker inspect {container}'.format(container=service_id))
        return json.loads(status)[0]['State']['Running']

    def service_logs(self, service):
        service_id = self._get_service_id(service)
        status = self._run_cmd('docker logs {container}'.format(container=service_id))
        return status

    def start(self, asset):
        if asset == self._running_asset:
            return
        elif self._running_asset != asset:
            self._stop(self._running_asset)
        self._start(asset)

    def stop(self):
        self._stop(self._running_asset)

    def _get_service_id(self, service):
        return self._run_cmd('docker-compose ps -q {}'.format(service)).strip()

    def _pause_services(self, *services):
        cmd = 'docker pause {}'
        for service in services:
            self._run_cmd(cmd.format(self._container_name(service)))

    def _resume_services(self, *services):
        cmd = 'docker unpause {}'
        for service in services:
            self._run_cmd(cmd.format(self._container_name(service)))

    @contextmanager
    def paused_service(self, service):
        self._pause_services(service)
        yield
        self._resume_services(service)

    def _container_name(self, service):
        contracted_asset_name = self._running_asset.replace('_', '')
        return '{asset}_{service}_1'.format(asset=contracted_asset_name, service=service)

    def _start(self, asset):
        self._running_asset = asset
        asset_path = os.path.join(os.path.dirname(__file__), '..', 'assets', asset)
        self.cur_dir = os.getcwd()
        os.chdir(asset_path)
        self._run_cmd('{} rm --force'.format(self._launcher))
        self._run_cmd('{} run --rm sync'.format(self._launcher))
        time.sleep(1)

    def _stop(self, asset):
        if not asset or asset != self._running_asset:
            return

        self._run_cmd('{} kill'.format(self._launcher))
        os.chdir(self.cur_dir)
        time.sleep(1)

    @staticmethod
    def _run_cmd(cmd):
        process = subprocess.Popen(cmd.split(' '), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = process.communicate()
        logger.info('%s', out)
        return out

    @classmethod
    def get_instance(cls):
        if not cls._instance:
            cls._instance = AssetRunner()
        return cls._instance


class _BaseTestCase(unittest.TestCase):

    url = 'https://{}:9497/0.1/token'.format(HOST)

    @classmethod
    def setUpClass(cls):
        cls._asset_runner = AssetRunner.get_instance()
        cls._asset_runner.start(cls.asset)

    @classmethod
    def tearDownClass(cls):
        cls._asset_runner.stop()

    def _post_token(self, username, password, backend=None, expiration=None):
        if not backend:
            backend = 'mock'
        s = requests.Session()
        s.headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        s.auth = requests.auth.HTTPBasicAuth(username, password)
        data = {'backend': backend}
        if expiration:
            data['expiration'] = expiration
        return s.post(self.url, data=json.dumps(data), verify=False)

    def _assert_that_xivo_auth_is_stopping(self):
        for _ in range(5):
            if not self._asset_runner.is_running('auth'):
                break
            time.sleep(0.2)
        else:
            self.fail('xivo-auth did not stop')


@unittest.skip('Skipped until python-consul implement a timeout')
class TestSlowConsul(_BaseTestCase):

    asset = 'mock_backend'

    def test_POST_when_consul_is_slow(self):
        start = time.time()

        with self._asset_runner.paused_service('consul'):
            response = self._post_token('foo', 'bar')

        end = time.time()
        assert_that(end - start, less_than(3))
        assert_that(response, is_(http_error(500, 'Connection to consul timedout')))

    def test_DELETE_when_consul_is_slow(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        start = time.time()
        with self._asset_runner.paused_service('consul'):
            response = requests.delete('{}/{}'.format(self.url, token), verify=False)

        end = time.time()
        assert_that(end - start, less_than(3))
        assert_that(response, is_(http_error(500, 'Connection to consul timedout')))

    def test_GET_when_consul_is_slow(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        start = time.time()
        with self._asset_runner.paused_service('consul'):
            response = requests.get('{}/{}'.format(self.url, token), verify=False)

        end = time.time()
        assert_that(end - start, less_than(3))
        assert_that(response, is_(http_error(500, 'Connection to consul timedout')))

    def test_HEAD_when_consul_is_slow(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        start = time.time()
        with self._asset_runner.paused_service('consul'):
            response = requests.head('{}/{}'.format(self.url, token), verify=False)

        end = time.time()
        assert_that(end - start, less_than(3))
        assert_that(response.status_code, equal_to(500))


class TestCoreMockBackend(_BaseTestCase):

    asset = 'mock_backend'

    def test_that_head_with_a_valid_token_returns_204(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        response = requests.head('{}/{}'.format(self.url, token), verify=False)

        assert_that(response.status_code, equal_to(204))

    def test_that_head_with_an_invalid_token_returns_404(self):
        response = requests.head('{}/{}'.format(self.url, 'abcdef'), verify=False)

        assert_that(response.status_code, equal_to(404))

    def test_backends(self):
        response = requests.get('https://{}:9497/0.1/backends'.format(HOST), verify=False)

        assert_that(response.json()['data'],
                    contains_inanyorder('mock', 'mock_with_uuid', 'broken_init', 'broken_verify_password'))

    def test_that_get_returns_the_auth_id(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        response = requests.get('{}/{}'.format(self.url, token), verify=False)

        assert_that(response.status_code, equal_to(200))
        assert_that(response.json()['data']['auth_id'], equal_to('a-mocked-uuid'))

    def test_that_get_returns_the_xivo_user_uuid(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        response = requests.get('{}/{}'.format(self.url, token), verify=False)

        assert_that(response.status_code, equal_to(200))
        assert_that(response.json()['data'], has_key('xivo_user_uuid'))

    def test_that_get_does_not_work_after_delete(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        requests.delete('{}/{}'.format(self.url, token), verify=False)
        response = requests.get('{}/{}'.format(self.url, token), verify=False)

        assert_that(response, is_(http_error(404, 'No such token')))

    def test_that_deleting_unexistant_token_returns_200(self):
        response = requests.delete('{}/{}'.format(self.url, _new_token_id()), verify=False)

        assert_that(response.status_code, equal_to(200))

    def test_that_the_wrong_password_returns_401(self):
        response = self._post_token('foo', 'not_bar')

        assert_that(response.status_code, equal_to(401))

    def test_that_the_right_credentials_return_a_token_with_datas(self):
        response = self._post_token('foo', 'bar', backend='mock_with_uuid')
        content = response.json()['data']
        token = content['token']
        auth_id = content['auth_id']
        xivo_user_uuid = content['xivo_user_uuid']
        acls = content['acls']

        assert_that(response.status_code, equal_to(200))
        assert_that(token, has_length(36))
        assert_that(auth_id, equal_to('a-mocked-auth-id'))
        assert_that(xivo_user_uuid, equal_to('a-mocked-xivo-user-uuid'))
        assert_that(acls, contains_inanyorder('foo', 'bar'))

    def test_that_an_unknown_type_returns_a_401(self):
        response = self._post_token('foo', 'not_bar', 'unexistant_backend')

        assert_that(response.status_code, equal_to(401))

    def test_that_an_broken_backend_returns_a_401(self):
        response = self._post_token('foo', 'not_bar', 'broken_verify_password')

        assert_that(response.status_code, equal_to(401))

    def test_that_no_type_returns_400(self):
        s = requests.Session()
        s.headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        s.auth = requests.auth.HTTPBasicAuth('foo', 'bar')

        response = s.post(self.url, verify=False)

        assert_that(response.status_code, equal_to(400))

    def test_the_expiration_argument(self):
        token_data = self._post_token('foo', 'bar', expiration=2).json()['data']

        creation_time = datetime.strptime(token_data['issued_at'], ISO_DATETIME)
        expiration_time = datetime.strptime(token_data['expires_at'], ISO_DATETIME)

        expiration = expiration_time - creation_time

        assert_that(1 <= expiration.seconds < 3)

    def test_the_expiration_argument_as_a_string(self):
        response = self._post_token('foo', 'bar', expiration="30")

        assert_that(response, is_(http_error(400, 'Invalid expiration')))

    def test_negative_expiration(self):
        response = self._post_token('foo', 'bar', expiration=-1)

        assert_that(response, is_(http_error(400, 'Invalid expiration')))

    def test_that_expired_tokens_are_not_valid(self):
        token = self._post_token('foo', 'bar', expiration=1).json()['data']['token']

        time.sleep(2)

        response = requests.head('{}/{}'.format(self.url, token), verify=False)

        assert_that(response.status_code, equal_to(404))

    def test_that_expired_tokens_are_removed(self):
        from consul import Consul
        consul = Consul(token='the_one_ring', host='localhost', port=8500, scheme='https', verify=False)

        token = self._post_token('foo', 'bar', expiration=1).json()['data']['token']
        key = 'xivo/xivo-auth/tokens/{}'.format(token)
        _, values = consul.kv.get(key, recurse=True)

        assert_that(values, not empty())

        for _ in range(10):
            _, values = consul.kv.get(key, recurse=True)
            if values is None:
                break
            time.sleep(1)
        else:
            self.fail('Keys are not removed')

    def test_that_invalid_unicode_acl_returns_403(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        response = requests.head('{}/{}'.format(self.url, token), verify=False, params={'scope': 'éric'})

        assert_that(response.status_code, equal_to(403))

    def test_that_unauthorized_acls_on_HEAD_return_403(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        response = requests.head('{}/{}'.format(self.url, token), verify=False, params={'scope': 'confd'})

        assert_that(response.status_code, equal_to(403))

    def test_that_unauthorized_acls_on_GET_return_403(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        response = requests.get('{}/{}'.format(self.url, token), verify=False, params={'scope': 'confd'})

        assert_that(response.status_code, equal_to(403))

    def test_that_authorized_acls_on_HEAD_return_204(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        response = requests.head('{}/{}'.format(self.url, token), verify=False, params={'scope': 'foo'})

        assert_that(response.status_code, equal_to(204))

    def test_that_authorized_acls_on_GET_return_200(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        response = requests.get('{}/{}'.format(self.url, token), verify=False, params={'scope': 'foo'})

        assert_that(response.status_code, equal_to(200))


class TestNoConsul(_BaseTestCase):

    asset = 'no_consul'

    def test_POST_with_no_consul_running(self):
        response = self._post_token('foo', 'bar')

        assert_that(response, is_(http_error(500, 'Connection to consul failed')))

    def test_DELETE_with_no_consul_running(self):
        response = requests.delete('{}/{}'.format(self.url, _new_token_id()), verify=False)

        assert_that(response, is_(http_error(500, 'Connection to consul failed')))

    def test_GET_with_no_consul_running(self):
        response = requests.get('{}/{}'.format(self.url, _new_token_id()), verify=False)

        assert_that(response, is_(http_error(500, 'Connection to consul failed')))

    def test_HEAD_with_no_consul_running(self):
        response = requests.head('{}/{}'.format(self.url, _new_token_id()), verify=False)

        assert_that(response.status_code, equal_to(500))


class TestNoRabbitMQ(_BaseTestCase):

    asset = 'no_rabbitmq'

    def test_POST_with_no_rabbitmq_running(self):
        response = self._post_token('foo', 'bar')

        assert_that(response, is_(http_error(500, 'Connection to rabbitmq failed')))

    def test_DELETE_with_no_rabbitmq_running(self):
        response = requests.delete('{}/{}'.format(self.url, 'foobar'), verify=False)

        assert_that(response, is_(http_error(500, 'Connection to rabbitmq failed')))


class TestNoSSLCertificate(_BaseTestCase):

    asset = 'no_ssl_certificate'

    def test_that_xivo_auth_stops_if_not_readable_ssl_certificate(self):
        self._assert_that_xivo_auth_is_stopping()

        log = self._asset_runner.service_logs('auth')
        assert_that(log, contains_string("No such file or directory: '/data/_common/ssl/no_server.crt'"))


class TestNoSSLKey(_BaseTestCase):

    asset = 'no_ssl_key'

    def test_that_xivo_auth_stops_if_not_readable_ssl_key(self):
        self._assert_that_xivo_auth_is_stopping()

        log = self._asset_runner.service_logs('auth')
        assert_that(log, contains_string("No such file or directory: '/data/_common/ssl/no_server.key'"))
