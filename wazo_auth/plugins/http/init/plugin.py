# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        config = dependencies['config']
        args = (dependencies['policy_service'], dependencies['user_service'], config)

        api.add_resource(http.Init, '/init', resource_class_args=args)
