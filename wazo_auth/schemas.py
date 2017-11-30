# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from marshmallow import Schema, fields, pre_load, post_load
from marshmallow.validate import Range
from xivo.mallow import fields as xfields
from xivo.mallow import validate


class BaseSchema(Schema):

    @pre_load
    def ensure_dict(self, data):
        return data or {}


class GroupRequestSchema(BaseSchema):

    name = xfields.String(validate=validate.Length(min=1, max=128), required=True)


class PolicySchema(BaseSchema):

    name = fields.String(validate=validate.Length(min=1, max=80), required=True)
    description = fields.String(allow_none=True, missing=None)
    acl_templates = fields.List(fields.String(), missing=[])


class TenantRequestSchema(BaseSchema):

    name = xfields.String(validate=validate.Length(min=1, max=128), required=True)


class TokenRequestSchema(Schema):
    backend = fields.String(required=True)
    expiration = fields.Integer(validate=Range(min=1))


def new_list_schema(default_sort_column):

    class ListSchema(BaseSchema):

        direction = fields.String(validate=validate.OneOf(['asc', 'desc']), missing='asc')
        order = fields.String(validate=validate.Length(min=1), missing=default_sort_column)
        limit = fields.Integer(validate=validate.Range(min=0), missing=None)
        offset = fields.Integer(validate=validate.Range(min=0), missing=0)
        search = fields.String(missing=None)

        @post_load(pass_original=True)
        def add_arbitrary_fields(self, data, original_data):
            for key, value in original_data.iteritems():
                data.setdefault(key, value)
            return data

    return ListSchema
