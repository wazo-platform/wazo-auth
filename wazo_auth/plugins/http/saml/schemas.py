# Copyright 2019-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo.mallow import fields
from xivo.mallow.validate import Length

from wazo_auth import schemas


class SAMLSessionIdSchema(schemas.BaseSchema):
    saml_session_id = fields.String(validate=Length(min=30, max=50))
