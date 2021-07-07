# Copyright 2018-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.http import AuthClientFacade
from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (
            AuthClientFacade(),
            dependencies['email_service'],
            dependencies['user_service'],
        )

        api.add_resource(
            http.PasswordReset,
            '/users/password/reset',
            resource_class_args=args,
        )
