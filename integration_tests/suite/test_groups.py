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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

from hamcrest import assert_that, has_entries
from mock import ANY
from .helpers import base


class TestGroups(base.MockBackendTestCase):

    def test_post(self):
        name = 'foobar'

        invalid_bodies = [
            {},
            {'name': None},
            {'name': 42},
            {42: False},
            {'not name': name},
        ]

        for body in invalid_bodies:
            base.assert_http_error(400, self.client.groups.new, **body)

        result = self.client.groups.new(name='foobar')
        base.assert_that(result, has_entries('uuid', ANY, 'name', name))

        base.assert_http_error(409, self.client.groups.new, name='foobar')
