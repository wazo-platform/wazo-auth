# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from .base import BaseDAO
from ..models import LDAPConfig
from ... import exceptions


class LDAPConfigDAO(BaseDAO):
    def get(self, tenant_uuid):
        ldap_config = self.session.query(LDAPConfig).get(tenant_uuid)
        if ldap_config:
            return {
                'tenant_uuid': ldap_config.tenant_uuid,
                'host': ldap_config.host,
                'port': ldap_config.port,
                'protocol_version': ldap_config.protocol_version,
                'protocol_security': ldap_config.protocol_security,
                'bind_dn': ldap_config.bind_dn,
                'bind_password': ldap_config.bind_password,
                'user_base_dn': ldap_config.user_base_dn,
                'user_login_attribute': ldap_config.user_login_attribute,
                'user_email_attribute': ldap_config.user_email_attribute,
            }
        raise exceptions.UnknownLDAPConfigException(tenant_uuid)
