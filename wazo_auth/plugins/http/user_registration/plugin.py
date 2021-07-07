# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (
            dependencies['email_service'],
            dependencies['tenant_service'],
            dependencies['user_service'],
        )

        api.add_resource(
            http.Register,
            '/users/register',
            resource_class_args=args,
        )
