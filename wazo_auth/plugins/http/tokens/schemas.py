# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from marshmallow import Schema, fields
from marshmallow.validate import Range


class TokenRequestSchema(Schema):
    backend = fields.String(required=True)
    expiration = fields.Integer(validate=Range(min=1))
