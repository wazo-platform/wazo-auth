# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from marshmallow import ValidationError, validates_schema
from wazo_auth.schemas import BaseSchema
from xivo.mallow import fields
from xivo.mallow.validate import Length


class ExternalAuthConfigQueryParameters(BaseSchema):

    client_id = fields.String(validate=Length(min=1, max=256))
    client_secret = fields.String(validate=Length(min=1, max=256))

