# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from marshmallow import post_load, validates_schema, ValidationError
from xivo.mallow import fields
from wazo_auth.schemas import BaseSchema


class _AdminEmailSchema(BaseSchema):

    address = fields.Email(required=True)
    confirmed = fields.Boolean(missing=None, allow_none=True)
    main = fields.Boolean(missing=False)


class AdminUserEmailPutSchema(BaseSchema):

    emails = fields.Nested(_AdminEmailSchema, many=True)

    @post_load
    def as_list(self, data):
        return data['emails']

    @validates_schema
    def validate_only_one_main(self, data):
        main = 0

        emails = data['emails']
        if not emails:
            return

        for email in emails:
            if email['main']:
                main += 1

        if main > 1:
            raise ValidationError('Only one address should be main')

        if main == 0:
            raise ValidationError('At least one address should be main')

    @validates_schema
    def validate_no_duplicates(self, data):
        addresses = set()

        for email in data['emails']:
            address = email.get('address')
            if not address:
                continue

            if address in addresses:
                raise ValidationError('The same address can only be used once')

            addresses.add(address)
