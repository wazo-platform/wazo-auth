# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Avencall
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

from datetime import datetime
from hamcrest import assert_that
from hamcrest import contains_inanyorder
from hamcrest import equal_to
from hamcrest import has_length

logger = logging.getLogger(__name__)

ISO_DATETIME = '%Y-%m-%dT%H:%M:%S.%f'

HOST = os.getenv('XIVO_AUTH_TEST_HOST', 'localhost')


class AssetRunner(object):

    _launcher = 'docker-compose'
    _instance = None

    def __init__(self):
        self._running_asset = None

    def __del__(self):
        if self._running_asset:
            self._stop(self._running_asset)

    def start(self, asset):
        if asset == self._running_asset:
            return
        elif self._running_asset != asset:
            self._stop(asset)
        self._start(asset)

    def _start(self, asset):
        self._running_asset = asset
        asset_path = os.path.join(os.path.dirname(__file__), '..', 'assets', asset)
        self.cur_dir = os.getcwd()
        os.chdir(asset_path)
        self._run_cmd('{} up -d'.format(self._launcher))
        time.sleep(1)

    def _stop(self, asset):
        if not asset or asset != self._running_asset:
            return

        self._run_cmd('{} kill'.format(self._launcher))
        self._run_cmd('{} rm --force'.format(self._launcher))
        os.chdir(self.cur_dir)
        time.sleep(1)

    @staticmethod
    def _run_cmd(cmd):
        process = subprocess.Popen(cmd.split(' '), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = process.communicate()
        logger.info('%s', out)

    @classmethod
    def get_instance(cls):
        if not cls._instance:
            cls._instance = AssetRunner()
        return cls._instance


class _BaseTestCase(unittest.TestCase):

    url = 'http://{}:9497/0.1/token'.format(HOST)

    @classmethod
    def setUpClass(cls):
        cls._asset_runner = AssetRunner.get_instance()
        cls._asset_runner.start(cls.asset)

    def _post_token(self, username, password, backend=None, expiration=None):
        if not backend:
            backend = 'mock'
        s = requests.Session()
        s.headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        s.auth = requests.auth.HTTPBasicAuth(username, password)
        data = {'backend': backend}
        if expiration:
            data['expiration'] = expiration
        return s.post(self.url, data=json.dumps(data))


class TestHEADToken(_BaseTestCase):

    asset = 'mock_backend'

    def test_that_head_with_a_valid_token_returns_204(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        response = requests.head('{}/{}'.format(self.url, token))

        assert_that(response.status_code, equal_to(204))

    def test_that_head_with_an_invalid_token_returns_403(self):
        response = requests.head('{}/{}'.format(self.url, 'abcdef'))

        assert_that(response.status_code, equal_to(404))


class TestGETBackends(_BaseTestCase):

    asset = 'mock_backend'

    def test_backends(self):
        response = requests.get('http://{}:9497/0.1/backends'.format(HOST))

        assert_that(response.json()['data'],
                    contains_inanyorder('mock', 'broken_init', 'broken_verify_password'))


class TestGETToken(_BaseTestCase):

    asset = 'mock_backend'

    def test_that_get_returns_the_uuid(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        response = requests.get('{}/{}'.format(self.url, token))

        assert_that(response.status_code, equal_to(200))
        assert_that(response.json()['data']['uuid'], equal_to('a-mocked-uuid'))


class TestDELETEToken(_BaseTestCase):

    asset = 'mock_backend'

    def test_that_get_does_not_work_after_delete(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        requests.delete('{}/{}'.format(self.url, token))
        response = requests.get('{}/{}'.format(self.url, token))

        assert_that(response.status_code, equal_to(404))

    def test_that_deleting_unexistant_token_returns_200(self):
        response = requests.delete('{}/{}'.format(self.url, 'not-a-valid-token'))

        assert_that(response.status_code, equal_to(200))


class TestTokenPost(_BaseTestCase):

    asset = 'mock_backend'

    def test_that_the_wrong_password_returns_401(self):
        response = self._post_token('foo', 'not_bar')

        assert_that(response.status_code, equal_to(401))

    def test_that_the_right_credentials_return_a_token(self):
        response = self._post_token('foo', 'bar')
        content = response.json()['data']
        token = content['token']

        assert_that(response.status_code, equal_to(200))
        assert_that(token, has_length(36))

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

        response = s.post(self.url)

        assert_that(response.status_code, equal_to(400))

    def test_the_expiration_argument(self):
        token_data = self._post_token('foo', 'bar', expiration=2).json()['data']

        creation_time = datetime.strptime(token_data['issued_at'], ISO_DATETIME)
        expiration_time = datetime.strptime(token_data['expires_at'], ISO_DATETIME)

        expiration = expiration_time - creation_time

        assert_that(1 < expiration.seconds < 3)

    def test_negative_expiration(self):
        response = self._post_token('foo', 'bar', expiration=-1)

        assert_that(response.status_code, equal_to(400))

    def test_that_expired_tokens_are_not_valid(self):
        token = self._post_token('foo', 'bar', expiration=1).json()['data']['token']

        time.sleep(2)

        response = requests.head('{}/{}'.format(self.url, token))

        assert_that(response.status_code, equal_to(404))
