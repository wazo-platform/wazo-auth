# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from marshmallow import ValidationError, validates_schema
from xivo.mallow import fields, validate

from wazo_auth.schemas import BaseSchema


class PasswordResetPostParameters(BaseSchema):
    password = fields.String(
        validate=validate.Length(min=1), required=True, allow_none=True
    )


class PasswordResetQueryParameters(BaseSchema):
    username = fields.String(
        validate=validate.Length(min=1, max=256), load_default=None
    )
    email_address = fields.Email(data_key='email', load_default=None)
    login = fields.String(validate=validate.Length(min=1, max=256), load_default=None)

    @validates_schema
    def validate_mutually_exclusive_fields(self, data, **kwargs):
        username = data.get('username')
        email = data.get('email_address')
        login = data.get('login')

        if (username, email, login).count(None) != 2:
            msg = '"username" or "email" or "login" should be used'
            raise ValidationError(msg)
