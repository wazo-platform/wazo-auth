# Copyright 2017-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from marshmallow import validates_schema
from marshmallow.exceptions import ValidationError

from xivo.mallow import fields
from xivo.mallow.validate import Length, Range, OneOf

from wazo_auth.schemas import BaseListSchema, BaseSchema


class TokenRequestSchema(BaseSchema):
    backend = fields.String(missing='wazo_user')
    expiration = fields.Integer(validate=Range(min=1))
    access_type = fields.String(validate=OneOf(['online', 'offline']))
    client_id = fields.String(validate=Length(min=1, max=1024))
    refresh_token = fields.String()
    tenant_id = fields.String()

    @validates_schema
    def check_access_type_usage(self, data, **kwargs):
        access_type = data.get('access_type')
        if access_type != 'offline':
            return

        refresh_token = data.get('refresh_token')
        if refresh_token:
            raise ValidationError(
                'cannot use the "access_type" "offline" with a refresh token'
            )

        client_id = data.get('client_id')
        if not client_id:
            raise ValidationError(
                '"client_id" must be specified when using "access_type" is "offline"'
            )

    @validates_schema
    def check_backend_type_for_tenant(self, data, **kwargs):
        backend = data.get('backend')
        if not backend == 'ldap_user':
            return

        tenant_id = data.get('tenant_id')
        if not tenant_id:
            raise ValidationError(
                '"tenant_id" must be specified when using ldap backend'
            )

    @validates_schema
    def check_refresh_token_usage(self, data, **kwargs):
        refresh_token = data.get('refresh_token')
        if not refresh_token:
            return

        client_id = data.get('client_id')
        if not client_id:
            raise ValidationError(
                '"client_id" must be specified when using a "refresh_token"'
            )


class RefreshTokenListSchema(BaseListSchema):
    sort_columns = ['created_at', 'client_id', 'mobile']
    default_sort_column = 'created_at'
    searchable_columns = ['created_at', 'client_id', 'mobile']


class RefreshTokenSchema(BaseSchema):

    client_id = fields.String(validate=Length(min=1, max=1024))
    created_at = fields.DateTime()
    mobile = fields.Boolean()
    user_uuid = fields.String()
    tenant_uuid = fields.String()


class TokenScopesRequestSchema(BaseSchema):
    scopes = fields.List(fields.String())
    tenant_uuid = fields.String(missing=None)
