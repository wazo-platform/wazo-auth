# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest import TestCase
from uuid import UUID
from hamcrest import assert_that, equal_to, has_entries

from .. import schemas


class _Address:

    _fields = ['line_1', 'line_2', 'city', 'state', 'country', 'zip_code']

    def __init__(self, **kwargs):
        for field in self._fields:
            setattr(self, field, kwargs.get(field, None))


class _Tenant:
    def __init__(self, contact=None, uuid=None, name=None, address=None, slug=None):
        self.uuid = uuid
        self.name = name
        self.address = address
        self.contact_uuid = contact
        self.slug = slug


class TestTenantSchema(TestCase):
    def setUp(self):
        self.schema = schemas.TenantFullSchema()

    def test_that_an_empty_address_returns_a_body(self):
        uuid = '9b644581-5799-4d36-9306-50483a4d4f28'
        tenant = _Tenant(uuid=uuid, slug='slug')

        result = self.schema.dump(tenant)

        assert_that(
            result,
            equal_to(
                {
                    'uuid': uuid,
                    'name': None,
                    'slug': 'slug',
                    'contact': None,
                    'phone': None,
                    'address': {
                        'line_1': None,
                        'line_2': None,
                        'city': None,
                        'state': None,
                        'country': None,
                        'zip_code': None,
                    },
                }
            ),
        )

    def test_with_an_address(self):
        uuid = 'e04f397c-0d52-4a83-aa8e-7ee374e9eed3'
        address = _Address(line_1='here', country='Canada')
        tenant = _Tenant(uuid=uuid, address=address, slug='address')

        result = self.schema.dump(tenant)

        assert_that(
            result,
            has_entries(
                uuid=uuid,
                name=None,
                slug='address',
                address={
                    'line_1': 'here',
                    'line_2': None,
                    'city': None,
                    'state': None,
                    'country': 'Canada',
                    'zip_code': None,
                },
            ),
        )

    def test_that_a_null_contact_is_accepted(self):
        body = {'contact': None, 'slug': 'nocontact'}

        result = self.schema.load(body)

        assert_that(result, has_entries(contact_uuid=None))

    def test_contact_uuid_fields_when_serializing(self):
        contact = 'e04f397c-0d52-4a83-aa8e-7ee374e9eed3'
        tenant = _Tenant(contact=contact, slug='slug')

        result = self.schema.dump(tenant)

        assert_that(result, has_entries(contact=contact))

    def test_uuid(self):
        body = {'name': 'foobar', 'slug': 'slug'}

        result = self.schema.load(body)

        assert_that(result, has_entries(uuid=None, name='foobar'))

        uuid_ = body['uuid'] = 'c5b146ac-a442-4d65-a087-09a5f943ca53'

        result = self.schema.load(body)

        assert_that(result, has_entries(uuid=UUID(uuid_), name='foobar'))
