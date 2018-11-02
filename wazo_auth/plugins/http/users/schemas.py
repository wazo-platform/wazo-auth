# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from xivo.mallow import fields
from xivo.mallow import validate
from wazo_auth.schemas import BaseSchema


class _BaseUserSchema(BaseSchema):

    username = fields.String(validate=validate.Length(min=1, max=256), required=True)
    firstname = fields.String(missing=None, allow_none=True)
    lastname = fields.String(missing=None, allow_none=True)
    purpose = fields.String(
        missing='user',
        validate=validate.OneOf(['user', 'internal', 'external_api'])
    )
    enabled = fields.Boolean(missing=True)


class UserPostSchema(_BaseUserSchema):

    uuid = fields.UUID()
    password = fields.String(validate=validate.Length(min=1), allow_none=True)
    email_address = fields.Email(allow_none=True)
    metadata_plugins = fields.Dict(validate=validate.validate_string_dict)


class UserPutSchema(_BaseUserSchema):
    pass


class ChangePasswordSchema(BaseSchema):

    old_password = fields.String(validate=validate.Length(min=1), required=True)
    new_password = fields.String(validate=validate.Length(min=1), required=True)
