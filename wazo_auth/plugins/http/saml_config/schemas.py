# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo.mallow import fields
from xivo.mallow.validate import Length

from wazo_auth.schemas import BaseSchema


class SamlConfig(BaseSchema):
    domain_uuid = fields.String(validate=Length(min=36, max=38), required=True)
    entity_id = fields.String(validate=Length(min=1, max=512), required=True)
    tenant_uuid = fields.String(validate=Length(min=36, max=38), required=False)


saml_config_schema = SamlConfig()


class SamlAcsUrl(BaseSchema):
    acs_url = fields.String(validate=Length(min=1, max=2083), required=True)


saml_acs_url_schema = SamlAcsUrl()
