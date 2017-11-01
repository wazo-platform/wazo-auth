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

import time
from functools import partial
from jinja2 import StrictUndefined, Template
from jinja2.exceptions import UndefinedError


class LazyTemplateRenderer(object):

    def __init__(self, acl_templates, get_data_fn, *args, **kwargs):
        self._acl_templates = acl_templates
        self._get_data_fn = get_data_fn
        self._args = args
        self._kwargs = kwargs
        self._data = {}
        self._initialized = False

    def render(self):
        acls = []
        for acl_template in self._acl_templates:
            for acl in self._evaluate_template(acl_template):
                acls.append(acl)
        return acls

    def _evaluate_template(self, acl_template):
        template = Template(acl_template, undefined=StrictUndefined)
        try:
            rendered_template = template.render(self._data)
            for acl in rendered_template.split('\n'):
                if acl:
                    yield acl
        except UndefinedError:
            # _data is only fetched if needed
            if self._initialized:
                return
            self._initialized = True
            self._data = self._get_data_fn(*self._args, **self._kwargs)
            for acl in self._evaluate_template(acl_template):
                if acl:
                    yield acl


class LocalTokenManager(object):

    def __init__(self, backend, token_manager):
        self._new_token = partial(token_manager.new_token, backend.obj, 'wazo-auth')
        self._remove_token = token_manager.remove_token
        self._token = None
        self._renew_time = time.time() - 5
        self._delay = 3600
        self._threshold = 30

    def get_token(self):
        if self._need_new_token():
            self._renew_time = time.time() + self._delay - self._threshold
            self._token = self._new_token({'expiration': 3600, 'backend': 'xivo_service'})

        return self._token.token

    def revoke_token(self):
        if self._token:
            self._remove_token(self._token.token)

    def _need_new_token(self):
        return not self._token or time.time() > self._renew_time
