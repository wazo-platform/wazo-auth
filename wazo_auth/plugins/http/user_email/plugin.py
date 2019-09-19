# Copyright 2018-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']

        email_service = dependencies['email_service']
        user_service = dependencies['user_service']

        api.add_resource(
            http.UserEmailConfirm,
            '/users/<uuid:user_uuid>/emails/<uuid:email_uuid>/confirm',
            resource_class_args=(email_service, user_service),
        )
        api.add_resource(
            http.AdminUserEmailUpdate,
            '/admin/users/<uuid:user_uuid>/emails',
            resource_class_args=(user_service,),
        )

        api.add_resource(
            http.UserEmailUpdate,
            '/users/<uuid:user_uuid>/emails',
            resource_class_args=(user_service,),
        )
