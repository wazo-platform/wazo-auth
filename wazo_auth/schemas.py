# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
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


class TenantSchema(BaseSchema):

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


class _BaseListSchema(mallow.ListSchema):
    recurse = fields.Boolean(missing=False)


class ExternalListSchema(_BaseListSchema):
    sort_columns = ['type']
    default_sort_column = 'type'
    searchable_columns = ['type']


class GroupListSchema(_BaseListSchema):
    sort_columns = ['name', 'uuid']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid']


class UserGroupListSchema(_BaseListSchema):
    sort_columns = ['name', 'uuid']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid']


class PolicyListSchema(_BaseListSchema):
    sort_columns = ['name', 'description', 'uuid']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid', 'group_uuid', 'tenant_uuid']


class GroupPolicyListSchema(_BaseListSchema):
    sort_columns = ['name', 'description', 'uuid']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid', 'group_uuid', 'tenant_uuid']


class TenantPolicyListSchema(_BaseListSchema):
    sort_columns = ['name', 'description', 'uuid']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid', 'group_uuid', 'tenant_uuid']


class UserPolicyListSchema(_BaseListSchema):
    sort_columns = ['name', 'description', 'uuid']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid', 'group_uuid', 'tenant_uuid']


class SessionListSchema(_BaseListSchema):
    sort_columns = ['mobile']


class UserSessionListSchema(_BaseListSchema):
    sort_columns = ['mobile']


class TenantListSchema(_BaseListSchema):
    sort_columns = ['name']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'uuids', 'name']


class UserTenantListSchema(_BaseListSchema):
    sort_columns = ['name']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'uuids', 'name']


class UserListSchema(_BaseListSchema):
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


class GroupUserListSchema(_BaseListSchema):
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


class TenantUserListSchema(_BaseListSchema):
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
