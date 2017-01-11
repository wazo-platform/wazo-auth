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
from mock import ANY, Mock

from ..database import Storage
from ..exceptions import InvalidInputException
from ..groups import Manager


class TestGroupManager(unittest.TestCase):

    def setUp(self):
        storage = Mock(Storage)
        self.manager = Manager(storage)

    def test_create_group_valid(self):
        name = 'valid'
        desc = 'A Valid description'
        input_and_expected = [
            (
                {'name': name},
                {'uuid': ANY,
                 'name': name,
                 'description': '',
                 'acls': []}
            ),
            (
                {'name': name, 'description': desc},
                {'uuid': ANY,
                 'name': name,
                 'description': desc,
                 'acls': []}
            )
        ]

        for group_data, expected in input_and_expected:
            group = self.manager.create(group_data)
            assert_that(group, equal_to(expected))

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
