# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo.mallow import fields, validate

from wazo_auth.schemas import DOMAIN_RE, BaseSchema


class SAMLSSOSchema(BaseSchema):
    redirect_url = fields.String(validate=validate.Length(min=1))
    domain = fields.String(validate=validate.Regexp(DOMAIN_RE))
