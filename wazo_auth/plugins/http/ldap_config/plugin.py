# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (
            dependencies['ldap_service'],
            dependencies['user_service'],
        )

        api.add_resource(
            http.LDAPConfig,
            '/backends/ldap',
            resource_class_args=args,
        )
