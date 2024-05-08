# Copyright 2017-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from . import http


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        args = (
            dependencies['token_service'],
            dependencies['user_service'],
            dependencies['saml_service'],
            dependencies['authentication_service'],
            dependencies['backends'],
        )

        api.add_resource(
            http.Tokens,
            '/token',
            resource_class_args=args,
        )
        api.add_resource(
            http.Token,
            '/token/<uuid:token_uuid>',
            resource_class_args=args,
        )
        api.add_resource(
            http.TokenScopesCheck,
            '/token/<uuid:token_uuid>/scopes/check',
            resource_class_args=args,
        )
        api.add_resource(
            http.RefreshTokens,
            '/tokens',
            resource_class_args=args,
        )
        api.add_resource(
            http.UserRefreshTokens,
            '/users/<uuid:user_uuid>/tokens',
            resource_class_args=args,
        )
        api.add_resource(
            http.UserRefreshToken,
            '/users/<uuid:user_uuid>/tokens/<string:client_id>',
            resource_class_args=args,
        )

        api.add_resource(
            http.UserMeRefreshTokens,
            '/users/me/tokens',
            resource_class_args=args,
        )
        api.add_resource(
            http.UserMeRefreshToken,
            '/users/me/tokens/<string:client_id>',
            resource_class_args=args,
        )
