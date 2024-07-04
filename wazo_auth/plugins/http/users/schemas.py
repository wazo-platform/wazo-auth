# Copyright 2017-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from marshmallow import pre_load
from xivo.mallow import fields, validate

from wazo_auth.schemas import BaseSchema


class _BaseUserSchema(BaseSchema):
    username = fields.String(
        validate=validate.Length(min=1, max=256), missing=None, allow_none=True
    )
    firstname = fields.String(missing=None, allow_none=True)
    lastname = fields.String(missing=None, allow_none=True)
    purpose = fields.String(
        missing='user', validate=validate.OneOf(['user', 'internal', 'external_api'])
    )
    authentication_method = fields.String(
        validate=validate.OneOf(['default', 'native', 'ldap', 'saml']),
    )
    enabled = fields.Boolean(missing=True)

    @pre_load
    def set_authentication_method(self, data, **kwargs):
        if not isinstance(data, dict):
            return data

        if 'authentication_method' not in data:
            purpose = data.get('purpose', 'user')
            if purpose in ['external_api', 'internal']:
                data['authentication_method'] = 'native'
            else:
                data['authentication_method'] = 'default'
        return data


class UserPostSchema(_BaseUserSchema):
    uuid = fields.UUID()
    password = fields.String(validate=validate.Length(min=1), allow_none=True)
    email_address = fields.Email(allow_none=True)


class UserPutSchema(_BaseUserSchema):
    pass


class ChangePasswordSchema(BaseSchema):
    old_password = fields.String(validate=validate.Length(min=1), required=True)
    new_password = fields.String(validate=validate.Length(min=1), required=True)
