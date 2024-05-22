# Copyright 2017-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo import mallow_helpers as mallow
from xivo.mallow import fields, validate

from wazo_auth.slug import Slug

BaseSchema = mallow.Schema

DOMAIN_RE = (
    r'^(?=.{1,253}\.?$)(?:(?!(-|_)|[^.]+_)[A-Za-z0-9-_]{1,}(?<!-)(?:\.|$)){2,63}$'
)


class GroupRequestSchema(BaseSchema):
    name = fields.String(validate=validate.Length(min=1, max=128), required=True)
    slug = fields.String(
        validate=[validate.Length(min=1, max=80), validate.Regexp(Slug.valid_re())],
        missing=None,
    )


class GroupPutSchema(GroupRequestSchema):
    slug = fields.String(dump_only=True)


class GroupFullSchema(BaseSchema):
    uuid = fields.String(dump_only=True)
    tenant_uuid = fields.String(dump_only=True)
    name = fields.String(validate=validate.Length(min=1, max=80), required=True)
    slug = fields.String(
        validate=[validate.Length(min=1, max=80), validate.Regexp(Slug.valid_re())],
        missing=None,
    )
    read_only = fields.Boolean(dump_only=True, attribute='system_managed')
    system_managed = fields.Boolean(dump_only=True)


class BaseListSchema(mallow.ListSchema):
    recurse = fields.Boolean(missing=False)


class ExternalListSchema(BaseListSchema):
    sort_columns = ['type']
    default_sort_column = 'type'
    searchable_columns = ['type']


class GroupListSchema(BaseListSchema):
    read_only = fields.Boolean()
    sort_columns = ['name', 'slug', 'uuid', 'read_only']
    default_sort_column = 'name'
    searchable_columns = [
        'uuid',
        'name',
        'slug',
        'user_uuid',
        'read_only',
        'policy_uuid',
        'policy_slug',
    ]


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


class UserPolicyListSchema(BaseListSchema):
    sort_columns = ['name', 'description', 'uuid']
    default_sort_column = 'name'
    searchable_columns = ['uuid', 'name', 'user_uuid', 'group_uuid', 'tenant_uuid']


class SessionListSchema(BaseListSchema):
    sort_columns = ['mobile']


class UserSessionListSchema(BaseListSchema):
    sort_columns = ['mobile']


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
        'policy_uuid',
        'policy_slug',
        'has_policy_uuid',
        'has_policy_slug',
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
