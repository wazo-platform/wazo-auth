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

import unittest

from hamcrest import assert_that, equal_to

from xivo_auth.plugins import backends


class TestXiVOServicePlugin(unittest.TestCase):

    def test_that_get_consul_acls_return_acls_from_config(self):
        config = {'services': {'xivo_service1': {'acls': [{'rule': 'xivo/private', 'policy': 'read'}]}}}
        backend = backends.XiVOService(config)

        result = backend.get_consul_acls('xivo_service1', {})

        assert_that(result, equal_to([{'rule': 'xivo/private', 'policy': 'read'}]))

    def test_that_get_ids_return_login(self):
        backend = backends.XiVOService({})

        result = backend.get_ids('xivo_service1', {})

        assert_that(result, equal_to(('xivo_service1', 'xivo_service1')))

    def test_that_verify_password_return_true_when_username_pwd_match(self):
        config = {'services': {'xivo_service1': {'service_key': 'xivo_service1_pwd'}}}
        backend = backends.XiVOService(config)

        result = backend.verify_password('xivo_service1', 'xivo_service1_pwd')

        assert_that(result, equal_to(True))

    def test_that_verify_password_return_false_when_username_pwd_not_match(self):
        config = {'services': {'xivo_service1': {'service_key': 'xivo_service1_pwd'}}}
        backend = backends.XiVOService(config)

        result = backend.verify_password('wrong_xivo_service_name', 'xivo_service1_pwd')

        assert_that(result, equal_to(False))
