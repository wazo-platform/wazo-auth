# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from threading import Timer

logger = logging.getLogger(__name__)


class ExpiredSessionRemover:

    def __init__(self, config, dao):
        self._dao = dao
        self._cleanup_interval = config['session_cleanup_interval']
        self._debug = config['debug']

    def run(self):
        self._cleanup()
        self._reschedule(self._cleanup_interval)

    def _cleanup(self):
        try:
            self._dao.session.delete_expired()
        except Exception:
            logger.warning('failed to remove expired sessions', exc_info=self._debug)

    def _reschedule(self, interval):
        t = Timer(interval, self.run)
        t.daemon = True
        t.start()
