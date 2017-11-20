# -*- coding: utf-8 -*-
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from wazo_auth import BaseAuthenticationBackend


class BackendMock(BaseAuthenticationBackend):

    def get_acls(self, login, args):
        return ['foo', 'bar', 'auth.#']

    def get_ids(self, login, agrs):
        return 'a-mocked-uuid', None

    def verify_password(self, login, password, args):
        return login == 'foo' and password == 'bar'


class BackendMockWithUUID(BaseAuthenticationBackend):

    def get_acls(self, login, args):
        return ['foo', 'bar']

    def get_ids(self, login, args):
        return 'a-mocked-auth-id', 'a-mocked-xivo-user-uuid'

    def verify_password(self, login, password, args):
        return login == 'foo' and password == 'bar'
