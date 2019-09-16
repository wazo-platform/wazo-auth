# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:

    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['group_service'],)

        api.add_resource(http.Group, '/groups/<uuid:group_uuid>', resource_class_args=args)
        api.add_resource(http.Groups, '/groups', resource_class_args=args)
