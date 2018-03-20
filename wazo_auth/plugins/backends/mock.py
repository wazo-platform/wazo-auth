# -*- coding: utf-8 -*-
# Copyright 2015-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from wazo_auth import BaseAuthenticationBackend


class _BaseMockBackend(BaseAuthenticationBackend):

    login, password = 'foo', 'bar'

    def load(self, dependencies):
        self._tenant_service = dependencies['tenant_service']

    def get_acls(self, login, args):
        return self._acls

    def get_metadata(self, login, args):
        metadata = super(_BaseMockBackend, self).get_metadata(login, args)
        metadata.update(self._base_metadata)
        metadata['tenants'] = self._format_tenants(self._tenants())
        return metadata

    def _format_tenants(self, tenants):
        result = []
        for tenant in tenants:
            result.append(
                {
                    'uuid': tenant['uuid'],
                    'name': tenant['name'],
                }
            )

        return result

    def _tenants(self):
        return []

    def verify_password(self, login, password, args):
        return (login, password) == (self.login, self.password)


class BackendMock(_BaseMockBackend):

    _base_metadata = {'auth_id': 'a-mocked-uuid'}
    _acls = ['foo', 'bar', 'auth.#']

    def _tenants(self):
        return self._tenant_service.list_(name='tenant-for-tests')


class BackendMockWithUUID(_BaseMockBackend):

    _base_metadata = {
        'auth_id': 'a-mocked-auth-id',
        'xivo_user_uuid': 'a-mocked-xivo-user-uuid',
    }
    _acls = ['foo', 'bar']


class BackendMockMultiTenant(_BaseMockBackend):

    _base_metadata = {
        'auth_id': 'a-mocked-auth-id',
    }
    _acls = ['foo', 'bar', 'auth.#']

    def _tenants(self):
        tenant1 = self._tenant_service.list_(name='multi-tenant1-for-tests')
        tenant2 = self._tenant_service.list_(name='multi-tenant2-for-tests')
        return tenant1 + tenant2
