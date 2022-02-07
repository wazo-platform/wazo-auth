# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import exc

from .base import BaseDAO
from ..models import LDAPConfig
from ... import exceptions


class LDAPConfigDAO(BaseDAO):
    def get(self, tenant_uuid):
        ldap_config = self.session.query(LDAPConfig).filter(
            LDAPConfig.tenant_uuid == tenant_uuid
        ).first()
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

    def create(
        self,
        tenant_uuid,
        host,
        port,
        user_base_dn,
        user_login_attribute,
        user_email_attribute,
        protocol_version=3,
        protocol_security=None,
        bind_dn=None,
        bind_password=None,
    ):
        ldap_config = LDAPConfig(
            tenant_uuid=tenant_uuid,
            host=host,
            port=port,
            user_base_dn=user_base_dn,
            user_login_attribute=user_login_attribute,
            user_email_attribute=user_email_attribute,
            protocol_version=protocol_version,
            protocol_security=protocol_security,
            bind_dn=bind_dn,
            bind_password=bind_password,
        )
        self.session.add(ldap_config)
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                raise exceptions.DuplicatedLDAPConfigException(tenant_uuid)
            raise
        return ldap_config.tenant_uuid
