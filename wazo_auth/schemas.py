# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from marshmallow import Schema, fields, pre_load, post_dump, post_load
from xivo.mallow import fields as xfields
from xivo.mallow import validate


class BaseSchema(Schema):

    @pre_load
    def ensure_dict(self, data):
        return data or {}


class GroupRequestSchema(BaseSchema):

    name = xfields.String(validate=validate.Length(min=1, max=128), required=True)


class TenantAddress(BaseSchema):

    line_1 = xfields.String(validate=validate.Length(min=1, max=256), missing=None, default=None)
    line_2 = xfields.String(validate=validate.Length(min=1, max=256), missing=None, default=None)
    city = xfields.String(validate=validate.Length(min=1, max=128), missing=None, default=None)
    state = xfields.String(validate=validate.Length(min=1, max=128), missing=None, default=None)
    country = xfields.String(validate=validate.Length(min=1, max=128), missing=None, default=None)
    zip_code = xfields.String(validate=validate.Length(min=1, max=16), missing=None, default=None)


class TenantSchema(BaseSchema):

    uuid = xfields.UUID(missing=None)
    parent_uuid = xfields.UUID(dump_only=True)
    name = xfields.String(validate=validate.Length(min=1, max=128), default=None, missing=None)
    contact_uuid = xfields.UUID(load_from='contact', dump_to='contact', missing=None, default=None)
    phone = xfields.String(validate=validate.Length(min=1, max=32), default=None, missing=None)
    address = xfields.Nested(TenantAddress, missing=dict, default=dict, allow_none=False)

    @post_dump
    def add_empty_address(self, data):
        data['address'] = data['address'] or TenantAddress().dump(data['address']).data
        return data


def new_list_schema(default_sort_column):

    class ListSchema(BaseSchema):

        direction = fields.String(validate=validate.OneOf(['asc', 'desc']), missing='asc')
        order = fields.String(validate=validate.Length(min=1), missing=default_sort_column)
        limit = fields.Integer(validate=validate.Range(min=0), missing=None)
        offset = fields.Integer(validate=validate.Range(min=0), missing=0)
        search = fields.String(missing=None)
        recurse = fields.Boolean(missing=False)

        @post_load(pass_original=True)
        def add_arbitrary_fields(self, data, original_data):
            for key, value in original_data.iteritems():
                data.setdefault(key, value)
            return data

    return ListSchema
