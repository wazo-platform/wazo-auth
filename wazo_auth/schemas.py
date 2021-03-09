# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from marshmallow import Schema, fields, pre_load, post_dump, EXCLUDE
from xivo.mallow import fields as xfields
from xivo.mallow import validate
from xivo import mallow_helpers as mallow


class BaseSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    @pre_load
    def ensure_dict(self, data):
        return data or {}


class GroupRequestSchema(BaseSchema):

    name = xfields.String(validate=validate.Length(min=1, max=128), required=True)


class TenantAddress(BaseSchema):

    line_1 = xfields.String(
        validate=validate.Length(min=1, max=256), missing=None, default=None
    )
    line_2 = xfields.String(
        validate=validate.Length(min=1, max=256), missing=None, default=None
    )
    city = xfields.String(
        validate=validate.Length(min=1, max=128), missing=None, default=None
    )
    state = xfields.String(
        validate=validate.Length(min=1, max=128), missing=None, default=None
    )
    country = xfields.String(
        validate=validate.Length(min=1, max=128), missing=None, default=None
    )
    zip_code = xfields.String(
        validate=validate.Length(min=1, max=16), missing=None, default=None
    )


empty_tenant_address = TenantAddress().dump({})


class TenantPUTSchema(BaseSchema):

    uuid = xfields.UUID(missing=None)
    parent_uuid = xfields.UUID(dump_only=True)
    name = xfields.String(
        validate=validate.Length(min=1, max=128), default=None, missing=None
    )
    contact_uuid = xfields.UUID(data_key='contact', missing=None, default=None)
    phone = xfields.String(
        validate=validate.Length(min=1, max=32), default=None, missing=None
    )
    address = xfields.Nested(
        TenantAddress,
        missing=empty_tenant_address,
        default=empty_tenant_address,
        allow_none=False,
    )

    @post_dump
    def add_empty_address(self, data):
        data['address'] = data['address'] or empty_tenant_address
        return data


class TenantFullSchema(BaseSchema):

    uuid = xfields.UUID(missing=None)
    parent_uuid = xfields.UUID(dump_only=True)
    name = xfields.String(
        validate=validate.Length(min=1, max=128), default=None, missing=None
    )
    slug = xfields.String(
        validate=[validate.Length(min=1, max=10), validate.Regexp(r'^[a-zA-Z0-9_]+$')],
        missing=None,
    )
    contact_uuid = xfields.UUID(data_key='contact', missing=None, default=None)
    phone = xfields.String(
        validate=validate.Length(min=1, max=32), default=None, missing=None
    )
    address = xfields.Nested(
        TenantAddress,
        missing=empty_tenant_address,
        default=empty_tenant_address,
        allow_none=False,
    )

    @post_dump
    def add_empty_address(self, data):
        data['address'] = data['address'] or empty_tenant_address
        return data


class BaseListSchema(mallow.ListSchema):
    recurse = fields.Boolean(missing=False)


class ExternalListSchema(BaseListSchema):
    sort_columns = ['type']
    default_sort_column = 'type'
    searchable_columns = ['type']


class GroupListSchema(BaseListSchema):
    system_managed = fields.Boolean()
    sort_columns = ['name', 'uuid', 'system_managed']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid', 'system_managed']


class UserGroupListSchema(BaseListSchema):
    sort_columns = ['name', 'uuid']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid']


class PolicyListSchema(BaseListSchema):
    sort_columns = ['name', 'description', 'uuid']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid', 'group_uuid', 'tenant_uuid']


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
