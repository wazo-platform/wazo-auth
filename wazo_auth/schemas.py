# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from marshmallow import post_dump, post_load
from xivo.mallow import fields, validate
from xivo import mallow_helpers as mallow

BaseSchema = mallow.Schema


class GroupRequestSchema(BaseSchema):

    name = fields.String(validate=validate.Length(min=1, max=128), required=True)


class TenantAddress(BaseSchema):

    line_1 = fields.String(
        validate=validate.Length(min=1, max=256), missing=None, default=None
    )
    line_2 = fields.String(
        validate=validate.Length(min=1, max=256), missing=None, default=None
    )
    city = fields.String(
        validate=validate.Length(min=1, max=128), missing=None, default=None
    )
    state = fields.String(
        validate=validate.Length(min=1, max=128), missing=None, default=None
    )
    country = fields.String(
        validate=validate.Length(min=1, max=128), missing=None, default=None
    )
    zip_code = fields.String(
        validate=validate.Length(min=1, max=16), missing=None, default=None
    )


empty_tenant_address = TenantAddress().dump({})


class TenantFullSchema(BaseSchema):

    uuid = fields.UUID(missing=None)
    parent_uuid = fields.UUID(dump_only=True)
    name = fields.String(
        validate=validate.Length(min=1, max=128), default=None, missing=None
    )
    slug = fields.String(
        validate=[validate.Length(min=1, max=10), validate.Regexp(r'^[a-zA-Z0-9_]+$')],
        missing=None,
    )
    contact_uuid = fields.UUID(data_key='contact', missing=None, default=None)
    phone = fields.String(
        validate=validate.Length(min=1, max=32), default=None, missing=None
    )
    domain_names = fields.List(
        fields.String(
            validate=validate.Regexp(
                r'^([A-Za-z0-9]\.|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.){1,3}[A-Za-z]{2,6}$'
            )
        ),
        missing=[],
        default=[],
        allow_none=False,
    )
    address = fields.Nested(
        TenantAddress,
        missing=empty_tenant_address,
        default=empty_tenant_address,
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


class BaseListSchema(mallow.ListSchema):
    recurse = fields.Boolean(missing=False)


class ExternalListSchema(BaseListSchema):
    sort_columns = ['type']
    default_sort_column = 'type'
    searchable_columns = ['type']


class GroupListSchema(BaseListSchema):
    read_only = fields.Boolean()
    sort_columns = ['name', 'uuid', 'read_only']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid', 'read_only']


class UserGroupListSchema(BaseListSchema):
    sort_columns = ['name', 'uuid']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid']


class PolicyListSchema(BaseListSchema):
    read_only = fields.Boolean()
    sort_columns = ['name', 'slug', 'description', 'uuid', 'read_only']
    default_sort_column = 'name'
    searchable_columns = [
        'uuid',
        'name',
        'slug',
        'user_uuid',
        'group_uuid',
        'tenant_uuid',
        'read_only',
    ]


class GroupPolicyListSchema(BaseListSchema):
    sort_columns = ['name', 'description', 'uuid']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid', 'group_uuid', 'tenant_uuid']


class TenantPolicyListSchema(BaseListSchema):
    sort_columns = ['name', 'description', 'uuid']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid', 'group_uuid', 'tenant_uuid']


class UserPolicyListSchema(BaseListSchema):
    sort_columns = ['name', 'description', 'uuid']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid', 'group_uuid', 'tenant_uuid']


class SessionListSchema(BaseListSchema):
    sort_columns = ['mobile']


class UserSessionListSchema(BaseListSchema):
    sort_columns = ['mobile']


class TenantListSchema(BaseListSchema):
    sort_columns = ['name', 'slug']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'uuids', 'name', 'slug']


class UserTenantListSchema(BaseListSchema):
    sort_columns = ['name']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'uuids', 'name']


class UserListSchema(BaseListSchema):
    sort_columns = ['username', 'firstname', 'lastname']
    default_sort_column = 'username'
    searchable_columns = [
        'uuid',
        'username',
        'firstname',
        'lastname',
        'purpose',
        'email_address',
        'group_uuid',
    ]


class GroupUserListSchema(BaseListSchema):
    sort_columns = ['username']
    default_sort_column = 'username'
    searchable_columns = [
        'uuid',
        'username',
        'firstname',
        'lastname',
        'purpose',
        'email_address',
        'group_uuid',
    ]


class TenantUserListSchema(BaseListSchema):
    sort_columns = ['username']
    default_sort_column = 'username'
    searchable_columns = [
        'uuid',
        'username',
        'firstname',
        'lastname',
        'purpose',
        'email_address',
        'group_uuid',
    ]
