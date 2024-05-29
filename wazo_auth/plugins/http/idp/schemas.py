# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo.mallow import fields

from wazo_auth.schemas import BaseSchema


class IDPUserSchema(BaseSchema):
    uuid = fields.String(required=True)


class IDPUsersSchema(BaseSchema):
    users = fields.Nested(IDPUserSchema, many=True, required=True)
