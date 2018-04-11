# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import assert_that, contains, contains_inanyorder, equal_to, has_entries
from mock import ANY
from .helpers import base, fixtures


class TestGroups(base.WazoAuthTestCase):

    asset = 'mock_backend'

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

    @fixtures.http_group(name='foobar')
    def test_post(self, result):
        name = 'foobar'

        assert_that(result, has_entries('uuid', ANY, 'name', name))

        for body in self.invalid_bodies:
            base.assert_http_error(400, self.client.groups.new, **body)

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
