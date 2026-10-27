# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo.mallow import fields
from xivo.mallow.validate import Length

from wazo_auth import schemas


class SalesforcePostSchema(schemas.BaseSchema):
    scope = fields.List(fields.String(validate=Length(min=1, max=512)))


class SalesforceLinkSchema(schemas.BaseSchema):
    access_token = fields.String()
    token_expiration = fields.Integer()
    scope = fields.String(dump_default=None)
    instance_url = fields.String(dump_default=None)
