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

import logging
import requests
import subprocess
import unittest
import time
import os

from hamcrest import assert_that
from hamcrest import equal_to

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

    @staticmethod
    def _run_cmd(cmd):
        process = subprocess.Popen(cmd.split(' '), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = process.communicate()
        logger.info(out)

    @classmethod
    def setUpClass(cls):
        cls.launch_services()

    @classmethod
    def tearDownClass(cls):
        cls.stop_services()

    def test_that_the_wrong_password_returns_401(self):
        params = dict(
            username='foo',
            password='not_bar',
            type='mock',
        )
        response = requests.post('http://localhost:9497/0.1/token', params=params)

        assert_that(response.status_code, equal_to(401))
