# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from xivo.mallow import fields
from xivo.mallow import validate
from wazo_auth.schemas import BaseSchema


class UserPostSchema(BaseSchema):

    uuid = fields.UUID()
    username = fields.String(validate=validate.Length(min=1, max=128), required=True)
    password = fields.String(validate=validate.Length(min=1))
    email_address = fields.Email(required=True)


class ChangePasswordSchema(BaseSchema):

    old_password = fields.String(validate=validate.Length(min=1), required=True)
    new_password = fields.String(validate=validate.Length(min=1), required=True)
