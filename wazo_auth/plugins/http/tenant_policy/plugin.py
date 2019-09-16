# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:

    def load(self, dependencies):
        api = dependencies['api']
        tenant_service = dependencies['tenant_service']

        api.add_resource(
            http.TenantPolicies,
            '/tenants/<uuid:tenant_uuid>/policies',
            resource_class_args=(tenant_service,),
        )
