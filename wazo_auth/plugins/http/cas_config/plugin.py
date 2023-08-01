# Copyright 2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['cas_service'],)

        api.add_resource(
            http.CASConfig,
            '/backends/cas',
            resource_class_args=args,
        )
