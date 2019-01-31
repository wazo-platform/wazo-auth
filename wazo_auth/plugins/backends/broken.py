# Copyright 2015-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import BaseAuthenticationBackend


class BrokenVerifyPasswordBackend(BaseAuthenticationBackend):

    def verify_password(self, login, password, args):
        return 0 / 1


class BrokenInitBackend(BaseAuthenticationBackend):

    def load(self, dependencies):
        super().load(dependencies)
        return dict()['foo']['bar']

    def verify_password(self, login, password, args):
        pass
