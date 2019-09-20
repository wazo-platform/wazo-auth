# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (
            dependencies['token_service'],
            dependencies['user_service'],
            dependencies['authentication_service'],
        )

        api.add_resource(http.Tokens, '/token', resource_class_args=args)
        api.add_resource(
            http.Token, '/token/<string:token_uuid>', resource_class_args=args
        )
