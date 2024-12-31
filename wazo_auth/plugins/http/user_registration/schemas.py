# Copyright 2017-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo.mallow import fields, validate

from wazo_auth.schemas import BaseSchema


class UserRegisterPostSchema(BaseSchema):
    username = fields.String(validate=validate.Length(min=1, max=256))
    password = fields.String(validate=validate.Length(min=1), required=True)
    firstname = fields.String(load_default=None)
    lastname = fields.String(load_default=None)
    email_address = fields.Email(required=True)
    purpose = fields.Constant('user')
    authentication_method = fields.Constant('default')
