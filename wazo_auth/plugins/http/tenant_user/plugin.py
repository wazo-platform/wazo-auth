# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:

    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['tenant_service'],)

        api.add_resource(
            http.TenantUsers,
            '/tenants/<uuid:tenant_uuid>/users',
            resource_class_args=args,
        )
        api.add_resource(
            http.UserTenants,
            '/users/<uuid:user_uuid>/tenants',
            resource_class_args=(dependencies['user_service'],),
        )
