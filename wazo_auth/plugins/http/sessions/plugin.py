# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from .http import Sessions


class Plugin:

    def load(self, dependencies):
        api = dependencies['api']
        session_service = dependencies['session_service']

        api.add_resource(Sessions, '/sessions', resource_class_args=[session_service])
