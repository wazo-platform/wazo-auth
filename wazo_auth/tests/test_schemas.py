# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from unittest import TestCase
from hamcrest import assert_that, empty, has_entries
from mock import ANY
from werkzeug.datastructures import MultiDict

from .. import schemas


class TestListSchema(TestCase):

    def setUp(self):
        self.Schema = schemas.new_list_schema('username')

    def test_that_none_pagination_fields_remain_untouched(self):
        args = MultiDict([
            ('direction', 'asc'),
            ('order', 'name'),
            ('limit', 42),
            ('offset', 4),
            ('search', 'foobar'),
            ('username', 'foobaz'),
        ])

        list_params, errors = self.Schema().load(args)

        assert_that(list_params, has_entries('username', 'foobaz', 'search', 'foobar'))
        assert_that(errors, empty())

    def test_that_errors_are_not_ignored_by_the_arbitrary_field_validator(self):
        args = MultiDict([
            ('direction', 'foobar'),
            ('search', 'term'),
        ])

        list_params, errors = self.Schema().load(args)

        assert_that(errors, has_entries('direction', ANY))
