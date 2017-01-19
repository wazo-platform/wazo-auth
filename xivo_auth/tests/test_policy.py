# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>

import unittest

from hamcrest import assert_that, calling, equal_to, raises
from mock import ANY, Mock, sentinel as s

from ..database import Storage
from ..exceptions import InvalidInputException
from ..policy import Manager


class TestPolicyManager(unittest.TestCase):

    def setUp(self):
        self.storage = Mock(Storage)
        self.manager = Manager(self.storage)

    def test_create_policy_valid(self):
        name = 'valid'
        desc = 'A Valid description'
        input_and_expected = [
            (
                {'name': name},
                {'uuid': ANY,
                 'name': name,
                 'description': '',
                 'acl_templates': []}
            ),
            (
                {'name': name, 'description': desc},
                {'uuid': ANY,
                 'name': name,
                 'description': desc,
                 'acl_templates': []}
            )
        ]

        for policy_data, expected in input_and_expected:
            policy = self.manager.create(policy_data)
            assert_that(policy, equal_to(expected))

    def test_that_invalid_values_raise_a_manager_exception(self):
        names = [
            None,
            True,
            False,
            '',
            42,
        ]

        for name in names:
            assert_that(
                calling(self.manager.create).with_args({'name': name}),
                raises(InvalidInputException)
            )

        descriptions = [
            None,
            True,
            False,
            42,
        ]
        for desc in descriptions:
            body = {'name': 'name', 'description': desc}
            assert_that(
                calling(self.manager.create).with_args(body),
                raises(InvalidInputException)
            )

    def test_that_invalid_acl_templates_raise_a_manager_exception(self):
        name = 'foobar'
        templates = [
            {'foo': 'bar'},
            42,
            True,
            False,
            None,
            'auth.*',
            [{'foo': 'bar'}],
            [42],
            ['#', False],
            [None],
        ]

        for template in templates:
            assert_that(
                calling(self.manager.create).with_args({
                    'name': name,
                    'acl_templates': template
                }), raises(InvalidInputException),
                template)

    def test_delete(self):
        self.manager.delete(s.policy_uuid)

        self.storage.delete_policy.assert_called_once_with(s.policy_uuid)
