# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from xivo.tenant_helpers import Tokens
from wazo_auth.http import AuthClientFacade

from . import http


class Plugin(object):

    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['user_service'],)
        tenant_args = (Tokens(AuthClientFacade()), Tokens(AuthClientFacade()))
        api.add_resource(http.Users, '/users', resource_class_args=args + tenant_args)
        api.add_resource(http.User, '/users/<string:user_uuid>', resource_class_args=args)
        api.add_resource(http.UserPassword, '/users/<string:user_uuid>/password', resource_class_args=args)
