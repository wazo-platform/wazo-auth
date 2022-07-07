# Copyright 2017-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import time
import uuid

from wazo_auth.database.helpers import commit_or_rollback

logger = logging.getLogger(__name__)

MAX_SLUG_LEN = 80
SLUG_LEN = 3


# NOTE(fblackburn): This helper is used by metadata plugin
class LocalTokenRenewer:
    def __init__(self, token_service, acl=None):
        self._acl = acl
        self._token_service = token_service
        self._token = None
        self._renew_time = time.time() - 5
        self._delay = 3600
        self._threshold = 30

    def get_token(self):
        # get_token MUST be called before any DB operations during the HTTP request
        # otherwise previous changes will be committed event if an error occurs later
        if self._need_new_token():
            self._renew_time = time.time() + self._delay - self._threshold
            self._token = self._token_service.new_token_internal(
                expiration=self._delay,
                acl=self._acl,
            )
            commit_or_rollback()

        return self._token.token

    def revoke_token(self):
        if self._token:
            self._token_service.remove_token(self._token.token)

    def _need_new_token(self):
        return not self._token or time.time() > self._renew_time


def is_uuid(value):
    try:
        uuid_obj = uuid.UUID(value, version=4)
    except ValueError:
        return False

    return str(uuid_obj) == value
