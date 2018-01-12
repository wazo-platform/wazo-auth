# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from unittest import TestCase
from hamcrest import assert_that, empty, equal_to, has_entries
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


class _Address(object):

    _fields = ['line_1', 'line_2', 'city', 'state', 'country', 'zip_code']

    def __init__(self, **kwargs):
        for field in self._fields:
            setattr(self, field, kwargs.get(field, None))


class _Tenant(object):

    def __init__(self, contact=None, uuid=None, name=None, address=None):
        self.uuid = uuid
        self.name = name
        self.address = address
        self.contact_uuid = contact


class TenantSchema(TestCase):

    def setUp(self):
        self.schema = schemas.TenantSchema()

    def test_that_an_empty_address_returns_a_body(self):
        uuid = '9b644581-5799-4d36-9306-50483a4d4f28'
        tenant = _Tenant(uuid=uuid)

        result = self.schema.dump(tenant).data

        assert_that(result, equal_to(dict(
            uuid=uuid,
            name=None,
            contact=None,
            phone=None,
            address=dict(
                line_1=None,
                line_2=None,
                city=None,
                state=None,
                country=None,
                zip_code=None))))

    def test_with_an_address(self):
        uuid = 'e04f397c-0d52-4a83-aa8e-7ee374e9eed3'
        address = _Address(line_1='here', country='Canada')
        tenant = _Tenant(uuid=uuid, address=address)

        result = self.schema.dump(tenant).data

        assert_that(result, has_entries(
            uuid=uuid,
            name=None,
            address=dict(
                line_1='here',
                line_2=None,
                city=None,
                state=None,
                country='Canada',
                zip_code=None)))

    def test_that_the_uuid_is_stripped_on_load(self):
        body = dict(
            uuid='5ac6c192-c5c3-4448-8b51-a0d701704ce9',
            name='foobar',
        )

        result = self.schema.load(body).data

        assert_that(result, equal_to(dict(
            name='foobar',
            contact_uuid=None,
            phone=None,
            address=dict(
                line_1=None,
                line_2=None,
                city=None,
                state=None,
                country=None,
                zip_code=None))))

    def test_that_a_null_contact_is_accepted(self):
        body = dict(contact=None)

        result = self.schema.load(body).data

        assert_that(result, equal_to(dict(
            name=None,
            contact_uuid=None,
            phone=None,
            address=dict(
                line_1=None,
                line_2=None,
                city=None,
                state=None,
                country=None,
                zip_code=None))))

    def test_contact_uuid_fields_when_serializing(self):
        contact = 'e04f397c-0d52-4a83-aa8e-7ee374e9eed3'
        tenant = _Tenant(contact=contact)

        result = self.schema.dump(tenant).data

        assert_that(result, has_entries(contact=contact))
