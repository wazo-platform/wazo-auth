# Copyright 2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo.mallow import fields
from wazo_auth.schemas import BaseSchema
from xivo.mallow.validate import Length


class CASConfig(BaseSchema):
    tenant_uuid = fields.String(dump_only=True, default=None)
    server_url = fields.String(validate=Length(max=512), required=True, default=None)
    service_url = fields.String(validate=Length(max=512), required=True, default=None)
    user_email_attribute = fields.String(
        validate=Length(max=64), required=True, default=None
    )


class CASConfigEdit(CASConfig):
    pass


cas_config_schema = CASConfig()
cas_config_edit_schema = CASConfigEdit()
