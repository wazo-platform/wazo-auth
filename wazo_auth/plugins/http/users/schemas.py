# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo.mallow import fields
from xivo.mallow import validate
from wazo_auth.schemas import BaseSchema
from marshmallow import post_load


class _BaseUserSchema(BaseSchema):

    username = fields.String(
        validate=validate.Length(min=1, max=256), missing=None, allow_none=True
    )
    firstname = fields.String(missing=None, allow_none=True)
    lastname = fields.String(missing=None, allow_none=True)
    purpose = fields.String(
        missing='user', validate=validate.OneOf(['user', 'internal', 'external_api'])
    )
    enabled = fields.Boolean(missing=True)


class UserPostSchema(_BaseUserSchema):

    uuid = fields.UUID()
    password = fields.String(validate=validate.Length(min=1), allow_none=True)
    email_address = fields.Email(allow_none=True)

    @post_load
    def _ensure_email_address_is_lower_case(self, data, **kwargs):
        if 'email_address' in data.keys():
            if data['email_address']:
                data['email_address'] = data['email_address'].lower()
        return data


class UserPutSchema(_BaseUserSchema):
    pass


class ChangePasswordSchema(BaseSchema):

    old_password = fields.String(validate=validate.Length(min=1), required=True)
    new_password = fields.String(validate=validate.Length(min=1), required=True)
