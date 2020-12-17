# Copyright 2017-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import uuid
import time

from functools import partial

from wazo_auth.database.helpers import commit_or_rollback

logger = logging.getLogger(__name__)


class LocalTokenRenewer:
    def __init__(self, backend, token_service, user_service, username='wazo-auth'):
        self._username = username
        self._new_token = partial(token_service.new_token, backend.obj, self._username)
        self._remove_token = token_service.remove_token
        self._user_service = user_service
        self._token = None
        self._renew_time = time.time() - 5
        self._delay = 3600
        self._threshold = 30

    def get_token(self):
        # get_token MUST be called before any DB operations during the HTTP request
        # otherwise previous changes will be commited event if an error occurs later
        if self._need_new_token():
            if not self._user_exists(self._username):
                logger.info(
                    '%s user not found no local token will be created', self._username
                )
                return

            self._renew_time = time.time() + self._delay - self._threshold
            self._token = self._new_token(
                {
                    'expiration': 3600,
                    'backend': 'wazo_user',
                    'user_agent': '',
                    'remote_addr': '127.0.0.1',
                }
            )
            commit_or_rollback()

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


def is_uuid(value):
    try:
        uuid_obj = uuid.UUID(value, version=4)
    except ValueError:
        return False

    return str(uuid_obj) == value
