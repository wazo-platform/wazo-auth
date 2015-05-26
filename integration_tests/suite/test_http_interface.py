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

from hamcrest import assert_that
from hamcrest import equal_to
from hamcrest import has_length

logger = logging.getLogger(__name__)


class TestTokenCreation(unittest.TestCase):

    asset = 'mock_backend'
    launcher = 'docker-compose'

    @classmethod
    def launch_services(cls):
        cls.container_name = cls.asset
        asset_path = os.path.join(os.path.dirname(__file__), '..', 'assets', cls.asset)
        cls.cur_dir = os.getcwd()
        os.chdir(asset_path)
        cls._run_cmd('{} up -d'.format(cls.launcher))
        time.sleep(1)

    @classmethod
    def stop_services(cls):
        cls._run_cmd('{} kill'.format(cls.launcher))
        cls._run_cmd('{} rm --force'.format(cls.launcher))
        os.chdir(cls.cur_dir)
        time.sleep(1)

    @staticmethod
    def _run_cmd(cmd):
        process = subprocess.Popen(cmd.split(' '), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = process.communicate()
        logger.info('%s', out)

    @classmethod
    def setUpClass(cls):
        cls.launch_services()

    @classmethod
    def tearDownClass(cls):
        cls.stop_services()

    def _post_token(self, username, password, backend=None):
        if not backend:
            backend = 'mock'
        s = requests.Session()
        s.headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        s.auth = requests.auth.HTTPBasicAuth(username, password)
        payload = json.dumps({'type': backend})
        return s.post('http://localhost:9497/0.1/token', data=payload)

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

        response = s.post('http://localhost:9497/0.1/token')

        assert_that(response.status_code, equal_to(400))

    def test_that_head_with_a_valid_token_returns_204(self):
        token = self._post_token('foo', 'bar').json()['data']['token']

        response = requests.head('http://localhost:9497/0.1/token/{}'.format(token))

        assert_that(response.status_code, equal_to(204))

    def test_that_head_with_an_invalid_token_returns_403(self):
        response = requests.head('http://localhost:9497/0.1/token/{}'.format('abcdef'))

        assert_that(response.status_code, equal_to(403))
