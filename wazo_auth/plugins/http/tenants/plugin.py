# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['tenant_service'],)

        api.add_resource(http.Tenants, '/tenants', resource_class_args=args)
        api.add_resource(
            http.Tenant, '/tenants/<string:tenant_uuid>', resource_class_args=args
        )
