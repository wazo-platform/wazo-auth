# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.services.helpers import BaseService

from .. import exceptions


class LDAPService(BaseService):
    def get(self, tenant_uuid):
        try:
            return self._dao.ldap_config.get(tenant_uuid)
        except exceptions.UnknownLDAPConfigException:
            return {}

    def create_or_update(self, **kwargs):
        if not self._dao.ldap_config.exists(kwargs['tenant_uuid']):
            tenant_uuid = self._dao.ldap_config.create(**kwargs)
            return self._dao.ldap_config.get(tenant_uuid)
        self._dao.ldap_config.update(**kwargs)
        return self._dao.ldap_config.get(kwargs['tenant_uuid'])

    def delete(self, tenant_uuid):
        return self._dao.ldap_config.delete(tenant_uuid)
