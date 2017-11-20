# -*- coding: utf-8 -*-
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from wazo_auth import BaseAuthenticationBackend


class BrokenVerifyPasswordBackend(BaseAuthenticationBackend):

    def get_ids(self, login, args):
        pass

    def verify_password(self, login, password, args):
        return 0 / 1


class BrokenInitBackend(BaseAuthenticationBackend):

    def load(self, dependencies):
        super(BrokenInitBackend, self).load(dependencies)
        return dict()['foo']['bar']

    def get_ids(self, login, args):
        pass

    def verify_password(self, login, password, args):
        pass
