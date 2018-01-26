# -*- coding: utf-8 -*-
# Copyright 2015-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from wazo_auth import BaseAuthenticationBackend


class _BaseMockBackend(BaseAuthenticationBackend):

    login, password = 'foo', 'bar'

    def get_acls(self, login, args):
        return self._acls

    def get_metadata(self, login, args):
        metadata = super(_BaseMockBackend, self).get_metadata(login, args)
        metadata.update(self._base_metadata)
        return metadata

    def verify_password(self, login, password, args):
        return (login, password) == (self.login, self.password)


class BackendMock(_BaseMockBackend):

    _base_metadata = dict(auth_id='a-mocked-uuid')
    _acls = ['foo', 'bar', 'auth.#']


class BackendMockWithUUID(_BaseMockBackend):

    _base_metadata = dict(auth_id='a-mocked-auth-id', xivo_user_uuid='a-mocked-xivo-user-uuid')
    _acls = ['foo', 'bar']
