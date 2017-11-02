# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>

import os
import random
import string
import requests

from functools import wraps

from wazo_auth import exceptions


A_SALT = os.urandom(64)


def _random_string(length):
    return ''.join(random.choice(string.ascii_lowercase) for _ in xrange(length))


def http_tenant(**tenant_args):
    if 'name' not in tenant_args:
        tenant_args['name'] = _random_string(20)

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            tenant = self.client.tenants.new(**tenant_args)
            try:
                result = decorated(self, tenant, *args, **kwargs)
            finally:
                try:
                    self.client.tenants.delete(tenant['uuid'])
                except requests.HTTPError:
                    pass
            return result
        return wrapper
    return decorator


def tenant(**tenant_args):
    if 'name' not in tenant_args:
        tenant_args['name'] = _random_string(20)

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            tenant_uuid = self._crud.create(**tenant_args)
            result = decorated(self, tenant_uuid, *args, **kwargs)
            try:
                self._crud.delete(tenant_uuid)
            except exceptions.UnknownTenantException:
                pass
            return result
        return wrapper
    return decorator


def user(**user_args):
    if 'username' not in user_args:
        user_args['username'] = _random_string(20)
    if 'email_address' not in user_args:
        user_args['email_address'] = '{}@example.com'.format(_random_string(50))
    if 'hash_' not in user_args:
        user_args['hash_'] = _random_string(64)
    if 'salt' not in user_args:
        user_args['salt'] = A_SALT

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(self, *args, **kwargs):
            user_uuid = self._crud.create(**user_args)
            result = decorated(self, user_uuid, *args, **kwargs)
            # TODO delete the user when the delete gets implemented
            return result
        return wrapper
    return decorator
