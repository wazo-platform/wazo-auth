# Copyright 2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo.mallow import fields

from wazo_auth import schemas


class MobileSchema(schemas.BaseSchema):
    token = fields.String(min=1, max=512, load_default=None)
    apns_token = fields.String(
        allow_none=True, max=512, load_default=None
    )  # deprecated
    apns_voip_token = fields.String(allow_none=True, max=512, load_default=None)
    apns_notification_token = fields.String(allow_none=True, max=512, load_default=None)
