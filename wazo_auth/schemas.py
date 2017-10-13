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


class TokenRequestSchema(Schema):
    backend = fields.String(required=True)
    expiration = fields.Integer(validate=Range(min=1))


class UserRequestSchema(Schema):

    username = xfields.String(validate=validate.Length(min=1), required=True)
    password = xfields.String(validate=validate.Length(min=1), required=True)
    email_address = xfields.Email(required=True)

    @pre_load
    def dont_ignore_none(self, body):
        if body is None:
            return {}

