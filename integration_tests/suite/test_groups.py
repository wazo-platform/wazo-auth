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

from hamcrest import assert_that, contains, contains_inanyorder, equal_to, has_entries
from mock import ANY
from .helpers import base, fixtures


class TestGroups(base.MockBackendTestCase):

    unknown_uuid = '00000000-0000-0000-0000-000000000000'
    invalid_bodies = [
        {},
        {'name': None},
        {'name': 42},
        {'not name': 'foobar'},
    ]

    @fixtures.http_group(name='foobar')
    def test_delete(self, foobar):
        base.assert_http_error(404, self.client.groups.delete, self.unknown_uuid)
        base.assert_no_error(self.client.groups.delete, foobar['uuid'])
        base.assert_http_error(404, self.client.groups.delete, foobar['uuid'])

        result = self.client.groups.list()
        assert_list_matches(result, 0, 0)

    @fixtures.http_group(name='foobar')
    def test_get(self, foobar):
        base.assert_http_error(404, self.client.groups.get, self.unknown_uuid)
        result = self.client.groups.get(foobar['uuid'])
        assert_that(result, equal_to(foobar))

    def test_post(self):
        name = 'foobar'

        for body in self.invalid_bodies:
            base.assert_http_error(400, self.client.groups.new, **body)

        result = self.client.groups.new(name='foobar')
        base.assert_that(result, has_entries('uuid', ANY, 'name', name))

        base.assert_http_error(409, self.client.groups.new, name='foobar')

    @fixtures.http_group(name='foobar')
    @fixtures.http_group(name='duplicate')
    def test_put(self, duplicate, group):
        base.assert_http_error(404, self.client.groups.edit, self.unknown_uuid, name='foobaz')
        base.assert_http_error(409, self.client.groups.edit, duplicate['uuid'], name='foobar')

        for body in self.invalid_bodies:
            base.assert_http_error(400, self.client.groups.edit, group['uuid'], **body)

        result = self.client.groups.edit(group['uuid'], name='foobaz')
        assert_that(result, has_entries('uuid', group['uuid'], 'name', 'foobaz'))

        result = self.client.groups.get(group['uuid'])
        assert_that(result, has_entries('uuid', group['uuid'], 'name', 'foobaz'))

    @fixtures.http_group(name='baz')
    @fixtures.http_group(name='bar')
    @fixtures.http_group(name='foo')
    @fixtures.http_group(name='foobaz')
    @fixtures.http_group(name='foobar')
    def test_list(self, foobar, foobaz, foo, bar, baz):
        total = 5

        result = self.client.groups.list()
        assert_list_matches(result, total, 5, 'baz', 'bar', 'foo', 'foobaz', 'foobar')

        result = self.client.groups.list(search='foo')
        assert_list_matches(result, total, 3, 'foo', 'foobar', 'foobaz')

        result = self.client.groups.list(name='foobar')
        assert_list_matches(result, total, 1, 'foobar')

        result = self.client.groups.list(order='name', direction='desc')
        assert_list_matches(result, total, 5, 'foobaz', 'foobar', 'foo', 'baz', 'bar', ordered=True)

        result = self.client.groups.list(order='name', limit=2)
        assert_list_matches(result, total, 5, 'bar', 'baz', ordered=True)

        result = self.client.groups.list(order='name', offset=2)
        assert_list_matches(result, total, 5, 'foo', 'foobar', 'foobaz', ordered=True)


def assert_list_matches(result, total, filtered, *names, **kwargs):
    list_matcher_fn = contains if kwargs.get('ordered', False) else contains_inanyorder
    list_matcher = list_matcher_fn(*[has_entries('name', name) for name in names])
    assert_that(result, has_entries('total', total, 'filtered', filtered, 'items', list_matcher))
