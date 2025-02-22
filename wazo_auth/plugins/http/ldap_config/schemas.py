# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo.mallow import fields
from xivo.mallow.validate import Length, OneOf, Range

from wazo_auth.schemas import BaseSchema


class LDAPConfig(BaseSchema):
    tenant_uuid = fields.String(dump_only=True, dump_default=None)
    host = fields.String(validate=Length(max=512), required=True, dump_default=None)
    port = fields.Integer(required=True, dump_default=None)
    protocol_version = fields.Integer(
        validate=Range(min=2, max=3), load_default=3, dump_default=None
    )
    protocol_security = fields.String(
        validate=OneOf(['ldaps', 'tls']),
        allow_none=True,
        dump_default=None,
    )
    bind_dn = fields.String(
        validate=Length(max=256), allow_none=True, dump_default=None
    )
    user_base_dn = fields.String(
        validate=Length(max=256), required=True, dump_default=None
    )
    user_login_attribute = fields.String(
        validate=Length(max=64), required=True, dump_default=None
    )
    user_email_attribute = fields.String(
        validate=Length(max=64), required=True, dump_default=None
    )
    search_filters = fields.String(allow_none=True, dump_default=None)


class LDAPConfigEdit(LDAPConfig):
    bind_password = fields.String(load_only=True, allow_none=True)


ldap_config_schema = LDAPConfig()
ldap_config_edit_schema = LDAPConfigEdit()
