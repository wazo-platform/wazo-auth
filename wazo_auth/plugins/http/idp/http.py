# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import http

IDP_TYPES = [
    'native',
    'ldap',
    'saml',
]


class AuthenticationMethods(http.ErrorCatchingResource):
    def get(self):
        items = IDP_TYPES
        count = len(items)
        return {'total': count, 'filtered': count, 'items': items}
