# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from . import http


class Plugin(object):

    def load(self, dependencies):
        api = dependencies['api']
        args = (
            dependencies['email_service'],
            dependencies['user_service'],
        )

        api.add_resource(
            http.UserEmailConfirm,
            '/users/<uuid:user_uuid>/emails/<uuid:email_uuid>/confirm',
            resource_class_args=args,
        )
