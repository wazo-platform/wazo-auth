# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo.mallow import fields
from wazo_auth.schemas import BaseSchema
from xivo.mallow.validate import Range, OneOf


class LDAPConfig(BaseSchema):
    tenant_uuid = fields.String()
    host = fields.String()
    port = fields.Integer()
    protocol_version = fields.Integer(validate=Range(min=2, max=3))
    protocol_security = fields.String(validate=OneOf(['ldaps', 'tls']), missing=None)
    bind_dn = fields.String()
    user_base_dn = fields.String()
    user_login_attribute = fields.String()
    user_email_attribute = fields.String()


class LDAPConfigEdit(LDAPConfig):
    bind_password = fields.String()
