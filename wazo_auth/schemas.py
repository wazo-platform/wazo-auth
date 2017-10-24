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

from marshmallow import Schema, fields, pre_load
from marshmallow.validate import Range
from xivo.mallow import fields as xfields
from xivo.mallow import validate


class BaseSchema(Schema):

    @pre_load
    def ensure_dict(self, data):
        return data or {}


class PolicySchema(BaseSchema):

    name = fields.String(validate=validate.Length(min=1, max=80), required=True)
    description = fields.String(allow_none=True, missing=None)
    acl_templates = fields.List(fields.String(), missing=[])


class TokenRequestSchema(Schema):
    backend = fields.String(required=True)
    expiration = fields.Integer(validate=Range(min=1))


class UserRequestSchema(BaseSchema):

    username = xfields.String(validate=validate.Length(min=1, max=128), required=True)
    password = xfields.String(validate=validate.Length(min=1), required=True)
    email_address = xfields.Email(required=True)


def new_list_schema(default_sort_column):

    class ListSchema(BaseSchema):

        direction = fields.String(validate=validate.OneOf(['asc', 'desc']), missing='asc')
        order = fields.String(validate=validate.Length(min=1), missing=default_sort_column)
        limit = fields.Integer(validate=validate.Range(min=0), missing=None)
        offset = fields.Integer(validate=validate.Range(min=0), missing=0)
        search = fields.String(missing=None)

    return ListSchema
