# Copyright 2018-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from marshmallow import post_load, post_dump
from xivo.mallow import fields, validate
from wazo_auth.schemas import BaseSchema

SLUG_REGEX = r'^[a-zA-Z0-9_]+$'


class PolicyFullSchema(BaseSchema):

    uuid = fields.String(dump_only=True)
    tenant_uuid = fields.String(dump_only=True)
    name = fields.String(validate=validate.Length(min=1, max=80), required=True)
    slug = fields.String(
        validate=[validate.Length(min=1, max=80), validate.Regexp(SLUG_REGEX)],
        missing=None,
    )
    description = fields.String(allow_none=True, missing=None)
    acl_templates = fields.List(fields.String(), missing=[])
    acl = fields.List(fields.String(), missing=[], attribute='acl')

    @post_load
    def deprecated_load_acl_templates(self, data):
        old_acl_name = data.pop('acl_templates')
        if not data['acl'] and old_acl_name:
            data['acl'] = old_acl_name
        return data

    @post_dump
    def deprecated_dump_acl_templates(self, data):
        data['acl_templates'] = data['acl']
        return data


class PolicyPutSchema(PolicyFullSchema):

    slug = fields.String(dump_only=True)


policy_full_schema = PolicyFullSchema()
policy_put_schema = PolicyPutSchema()
