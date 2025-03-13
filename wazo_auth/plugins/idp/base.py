# Copyright 2019-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.interfaces import IDPPlugin, IDPPluginDependencies
from wazo_auth.services.tenant import TenantService
from wazo_auth.services.user import UserService


class BaseIDPDependencies(IDPPluginDependencies):
    user_service: UserService
    tenant_service: TenantService


class BaseIDP(IDPPlugin):
    _user_service: UserService
    _tenant_service: TenantService

    def load(self, dependencies: BaseIDPDependencies):
        self._user_service = dependencies['user_service']
        self._tenant_service = dependencies['tenant_service']

    def _get_user_auth_method(self, login):
        user = self._user_service.get_user_by_login(login)
        # TODO: can we push default auth method resolution to the db/dao layer?
        if user.authentication_method == 'default':
            tenant = self._tenant_service.get(None, user.tenant_uuid)
            authorized_method = tenant['default_authentication_method']
        else:
            authorized_method = user.authentication_method
        return authorized_method
