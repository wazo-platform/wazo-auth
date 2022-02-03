# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.flask_helpers import Tenant
from wazo_auth.http import AuthResource

from xivo.auth_verifier import required_acl


class LDAPConfig(AuthResource):
    def __init__(self, ldap_service):
        self._ldap_service = ldap_service

    @required_acl('auth.backends.ldap.read')
    def get(self):
        scoping_tenant = Tenant.autodetect()
        return self._ldap_service.get_config(scoping_tenant), 200
