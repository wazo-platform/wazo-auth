# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import time

from functools import partial
from jinja2 import StrictUndefined, Template
from jinja2.exceptions import UndefinedError

logger = logging.getLogger(__name__)


class LazyTemplateRenderer:

    def __init__(self, acl_templates, get_data_fn, *args, **kwargs):
        self._acl_templates = acl_templates
        self._get_data_fn = get_data_fn
        self._args = args
        self._kwargs = kwargs
        self._data = kwargs.get('metadata', {})
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
            for acl in rendered_template.split(':'):
                if acl:
                    yield acl
        except UndefinedError as e:
            # _data is only fetched if needed
            if self._initialized:
                logger.debug('Missing data when rendering ACL template: %s', e)
                return
            self._initialized = True
            remote_data = self._get_data_fn(*self._args, **self._kwargs)
            remote_data.update(self._data)
            self._data = remote_data
            for acl in self._evaluate_template(acl_template):
                if acl:
                    yield acl


class LocalTokenRenewer:

    def __init__(self, backend, token_service, user_service):
        self._username = 'wazo-auth'
        self._new_token = partial(token_service.new_token, backend.obj, self._username)
        self._remove_token = token_service.remove_token
        self._user_service = user_service
        self._token = None
        self._renew_time = time.time() - 5
        self._delay = 3600
        self._threshold = 30

    def get_token(self):
        if self._need_new_token():
            if not self._user_exists(self._username):
                logger.info('%s user not found no local token will be created', self._username)
                return

            self._renew_time = time.time() + self._delay - self._threshold
            self._token = self._new_token({'expiration': 3600, 'backend': 'wazo_user'})

        return self._token.token

    def _user_exists(self, username):
        if self._user_service.list_users(username=username):
            return True
        return False

    def revoke_token(self):
        if self._token:
            self._remove_token(self._token.token)

    def _need_new_token(self):
        return not self._token or time.time() > self._renew_time
