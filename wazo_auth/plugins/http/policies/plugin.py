# Copyright 2017-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['policy_service'],)

        api.add_resource(
            http.Policies,
            '/policies',
            resource_class_args=args,
        )
        api.add_resource(
            http.Policy,
            '/policies/<string:policy_uuid>',
            resource_class_args=args,
        )
        api.add_resource(
            http.PolicyAccess,
            '/policies/<string:policy_uuid>/acl_templates/<access>',
            endpoint='policyacltemplate',
            resource_class_args=args,
        )
        api.add_resource(
            http.PolicyAccess,
            '/policies/<string:policy_uuid>/acl/<access>',
            resource_class_args=args,
        )
