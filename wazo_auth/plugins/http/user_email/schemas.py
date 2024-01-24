# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from marshmallow import ValidationError, post_load, validates_schema
from xivo.mallow import fields

from wazo_auth.schemas import BaseSchema


class _AdminEmailSchema(BaseSchema):
    address = fields.Email(required=True)
    confirmed = fields.Boolean(missing=None, allow_none=True)
    main = fields.Boolean(missing=False)


class _UserEmailSchema(BaseSchema):
    address = fields.Email(required=True)
    main = fields.Boolean(missing=False)


class _EmailPutSchema(BaseSchema):
    @post_load
    def as_list(self, data, **kwargs):
        return data['emails']

    @validates_schema
    def validate_only_one_main(self, data, **kwargs):
        emails = data.get('emails')
        if not emails:
            return

        main_emails_count = [email['main'] for email in emails].count(True)

        if main_emails_count > 1:
            raise ValidationError('Only one address should be main')

        if main_emails_count == 0:
            raise ValidationError('At least one address should be main')

    @validates_schema
    def validate_no_duplicates(self, data, **kwargs):
        emails = data.get('emails')
        if not emails:
            return

        addresses = list(email['address'] for email in emails if email.get('address'))
        if len(addresses) != len(set(addresses)):
            raise ValidationError('The same address can only be used once')


class AdminEmailPutSchema(_EmailPutSchema):
    emails = fields.Nested(_AdminEmailSchema, required=True, many=True)


class UserEmailPutSchema(_EmailPutSchema):
    emails = fields.Nested(_UserEmailSchema, required=True, many=True)
