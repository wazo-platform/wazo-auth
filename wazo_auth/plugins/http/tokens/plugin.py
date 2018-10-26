# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from . import http


class Plugin:

    def load(self, dependencies):
        api = dependencies['api']
        args = (
            dependencies['token_manager'],
            dependencies['backends'],
            dependencies['user_service'],
        )

        api.add_resource(http.Tokens, '/token', resource_class_args=args)
        api.add_resource(http.Token, '/token/<string:token>', resource_class_args=args)
