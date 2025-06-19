# Copyright 2017-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from marshmallow import validates_schema
from marshmallow.exceptions import ValidationError
from xivo.mallow import fields
from xivo.mallow.validate import Length, OneOf, Range

from wazo_auth.schemas import BaseListSchema, BaseSchema

TEN_YEARS = 3600 * 24 * 365 * 10


class TokenRequestSchema(BaseSchema):
    backend = fields.String(load_default='wazo_user')
    expiration = fields.Integer(validate=Range(min=1, max=TEN_YEARS))
    access_type = fields.String(validate=OneOf(['online', 'offline']))
    client_id = fields.String(validate=Length(min=1, max=1024))
    saml_session_id = fields.String(validate=Length(min=1, max=1024))
    refresh_token = fields.String()
    tenant_id = fields.String()
    domain_name = fields.String()

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
    def check_backend_type_for_tenant_id_and_domain_name(self, data, **kwargs):
        tenant_id = data.get('tenant_id')
        domain_name = data.get('domain_name')
        if tenant_id and domain_name:
            raise ValidationError(
                '"tenant_id" and "domain_name" must be mutually exclusive'
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

    @validates_schema
    def check_saml_sesssion_id_or_credentials(self, data, **kwargs):
        saml_session_id = data.get('saml_session_id')
        refresh_token = data.get('refresh_token')

        if saml_session_id and refresh_token:
            raise ValidationError(
                'Cannot use a "saml_session_id" and a "refresh_token" at the same time'
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
    metadata = fields.Dict()


class TokenScopesRequestSchema(BaseSchema):
    scopes = fields.List(fields.String())
    tenant_uuid = fields.String(load_default=None)
