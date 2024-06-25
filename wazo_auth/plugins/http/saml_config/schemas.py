# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo.mallow import fields
from xivo.mallow.validate import Length

from wazo_auth.schemas import BaseSchema


class SamlConfig(BaseSchema):
    entity_id = fields.String(validate=Length(min=1, max=512), required=True)


saml_config_schema = SamlConfig()


class SamlAcsUrl(BaseSchema):
    acsrl = fields.String(validate=Length(min=1, max=2083), required=True)


saml_acs_url_schema = SamlAcsUrl()
