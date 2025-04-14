# Copyright 2017-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import threading
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
        self._delay = 3600
        self._threshold = 30
        self._lock = threading.RLock()

    def get_token(self):
        # get_token MUST be called before any DB operations during the HTTP request
        # otherwise previous changes will be committed event if an error occurs later
        with self._lock:
            if self._need_new_token():
                time_start = time.time()
                self._token = self._token_service.new_token_internal(
                    expiration=self._delay,
                    acl=self._acl,
                )
                commit_or_rollback()
                logger.info(
                    'Generated internal token in %.3fs: %s with expiration %ss',
                    time.time() - time_start,
                    self._token.token_redacted(),
                    self._delay,
                )

        return self._token.token

    def revoke_token(self):
        with self._lock:
            if self._token:
                self._token_service.remove_token(self._token.token)
                self._token = None

    def _need_new_token(self):
        if not self._token:
            return True
        expire_in = self._token.expire_t - time.time()
        return expire_in < self._threshold


def is_uuid(value):
    try:
        uuid_obj = uuid.UUID(value, version=4)
    except ValueError:
        return False

    return str(uuid_obj) == value
