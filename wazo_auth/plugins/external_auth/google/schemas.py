# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import schemas
from xivo.mallow import fields
from xivo.mallow.validate import Length


class GoogleSchema(schemas.BaseSchema):

    scope = fields.List(fields.String(validate=Length(min=1, max=512)))
    access_token = fields.String(dump_only=True)
    token_expiration = fields.Integer(dump_only=True)
