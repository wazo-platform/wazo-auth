# Copyright 2017-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from marshmallow import post_dump, post_load
from xivo.mallow import fields, validate

from wazo_auth.schemas import DOMAIN_RE, BaseListSchema, BaseSchema
from wazo_auth.slug import TenantSlug


class TenantListSchema(BaseListSchema):
    uuids = fields.MultiDictAwareList(fields.String, validate=validate.Length(max=25))
    sort_columns = ['name', 'slug']
    default_sort_column = 'name'
    searchable_columns = [
        'uuid',
        'uuids',
        'name',
        'slug',
        'domain_name',
    ]


class TenantAddress(BaseSchema):
    line_1 = fields.String(
        validate=validate.Length(min=1, max=256), load_default=None, dump_default=None
    )
    line_2 = fields.String(
        validate=validate.Length(min=1, max=256), load_default=None, dump_default=None
    )
    city = fields.String(
        validate=validate.Length(min=1, max=128), load_default=None, dump_default=None
    )
    state = fields.String(
        validate=validate.Length(min=1, max=128), load_default=None, dump_default=None
    )
    country = fields.String(
        validate=validate.Length(min=1, max=128), load_default=None, dump_default=None
    )
    zip_code = fields.String(
        validate=validate.Length(min=1, max=16), load_default=None, dump_default=None
    )


empty_tenant_address = TenantAddress().dump({})


class TenantFullSchema(BaseSchema):
    uuid = fields.UUID(load_default=None)
    parent_uuid = fields.UUID(dump_only=True)
    name = fields.String(
        validate=validate.Length(min=1, max=128), dump_default=None, load_default=None
    )
    slug = fields.String(
        validate=[
            validate.Length(min=1, max=10),
            validate.Regexp(TenantSlug.valid_re()),
        ],
        load_default=None,
    )
    contact_uuid = fields.UUID(data_key='contact', load_default=None, dump_default=None)
    phone = fields.String(
        validate=validate.Length(min=1, max=32), dump_default=None, load_default=None
    )
    default_authentication_method = fields.String(
        load_default='native',
        allow_none=False,
    )
    domain_names = fields.List(
        fields.String(validate=validate.Regexp(DOMAIN_RE)),
        load_default=[],
        dump_default=[],
        allow_none=False,
    )
    address = fields.Nested(
        TenantAddress,
        load_default=empty_tenant_address,
        dump_default=empty_tenant_address,
        allow_none=False,
    )

    @post_dump
    def add_empty_address(self, data, **kwargs):
        data['address'] = data['address'] or empty_tenant_address
        return data

    @post_load
    def ensure_domain_names_are_unique(self, data, **kwargs):
        data['domain_names'] = sorted(list(set(data['domain_names'])))
        return data


class TenantPUTSchema(TenantFullSchema):
    slug = fields.String(dump_only=True)
