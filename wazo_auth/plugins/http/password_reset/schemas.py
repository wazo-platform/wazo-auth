# Copyright 2018-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from marshmallow import ValidationError, validates_schema
from wazo_auth.schemas import BaseSchema
from xivo.mallow import fields, validate


class PasswordResetPostParameters(BaseSchema):

    password = fields.String(
        validate=validate.Length(min=1), required=True, allow_none=True
    )


class PasswordResetQueryParameters(BaseSchema):

    username = fields.String(validate=validate.Length(min=1, max=256), missing=None)
    email_address = fields.Email(data_key='email', missing=None)

    @validates_schema
    def validate_mutually_exclusive_fields(self, data):
        username = data.get('username')
        email = data.get('email_address')

        if (username, email).count(None) != 1:
            msg = '"username" or "email" should be used'
            raise ValidationError(msg)
