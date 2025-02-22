# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from marshmallow import post_dump
from xivo.mallow import fields, validate

from wazo_auth.schemas import BaseSchema
from wazo_auth.slug import Slug


class PolicyFullSchema(BaseSchema):
    uuid = fields.String(dump_only=True)
    tenant_uuid = fields.String(dump_only=True, attribute='tenant_uuid_exposed')
    name = fields.String(validate=validate.Length(min=1, max=80), required=True)
    slug = fields.String(
        validate=[validate.Length(min=1, max=80), validate.Regexp(Slug.valid_re())],
        load_default=None,
    )
    description = fields.String(allow_none=True, load_default=None)
    acl = fields.List(fields.String(), load_default=[], attribute='acl')
    read_only = fields.Boolean(dump_only=True)
    shared = fields.Boolean(load_default=False)

    @post_dump(pass_original=True)
    def set_shared_exposed_only_for_dump(self, data, original, **kwargs):
        data['shared'] = original.shared_exposed
        return data


class PolicyPutSchema(PolicyFullSchema):
    slug = fields.String(dump_only=True)
    shared = fields.String(dump_only=True)


policy_full_schema = PolicyFullSchema()
policy_put_schema = PolicyPutSchema()
