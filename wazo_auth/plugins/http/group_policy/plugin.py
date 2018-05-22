# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from . import http


class Plugin(object):

    def load(self, dependencies):
        api = dependencies['api']
        args = (
            dependencies['group_service'],
            dependencies['policy_service'],
        )

        api.add_resource(
            http.GroupPolicy,
            '/groups/<uuid:group_uuid>/policies/<uuid:policy_uuid>',
            resource_class_args=args,
        )

        api.add_resource(
            http.GroupPolicies,
            '/groups/<uuid:group_uuid>/policies',
            resource_class_args=args,
        )
