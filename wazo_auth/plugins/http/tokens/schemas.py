# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from marshmallow import Schema, fields
from marshmallow.validate import Range


class TokenRequestSchema(Schema):
    backend = fields.String(missing='wazo_user')
    expiration = fields.Integer(validate=Range(min=1))
