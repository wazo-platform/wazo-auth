# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['group_service'], dependencies['policy_service'])

        api.add_resource(
            http.GroupPolicyUUID,
            '/groups/<uuid:group_uuid>/policies/<uuid:policy_uuid>',
            resource_class_args=args,
        )
        api.add_resource(
            http.GroupPolicySlug,
            '/groups/<uuid:group_uuid>/policies/<string:policy_slug>',
            resource_class_args=args,
        )
        api.add_resource(
            http.GroupPolicies,
            '/groups/<uuid:group_uuid>/policies',
            resource_class_args=args,
        )
