# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time
import unittest

from sqlalchemy import create_engine, text

from wazo_auth.database.helpers import (
    ADVISORY_LOCK_CLASSID,
    SCHEDULER_LOCK_OBJID,
    SchedulerLeaderLock,
)

from .helpers import base
from .helpers.constants import DB_URI

LOCK_PARAMS = {'classid': ADVISORY_LOCK_CLASSID, 'objid': SCHEDULER_LOCK_OBJID}


@base.use_asset('database')
class TestSchedulerLeaderLock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        port = base.DBAssetLaunchingTestCase.service_port(5432, 'postgres')
        cls.uri = DB_URI.format(port=port)
        cls.observer = create_engine(cls.uri, isolation_level='AUTOCOMMIT')

    @classmethod
    def tearDownClass(cls):
        cls.observer.dispose()

    def setUp(self):
        self.engine_a = create_engine(self.uri)
        self.engine_b = create_engine(self.uri)
        self.lock_a = SchedulerLeaderLock(self.engine_a)
        self.lock_b = SchedulerLeaderLock(self.engine_b)

    def tearDown(self):
        self.lock_a.release()
        self.lock_b.release()
        self.engine_a.dispose()
        self.engine_b.dispose()

    def _granted_locks(self):
        with self.observer.connect() as connection:
            return connection.execute(
                text(
                    'SELECT count(*) FROM pg_locks '
                    "WHERE locktype = 'advisory' "
                    'AND classid = :classid AND objid = :objid AND granted'
                ),
                LOCK_PARAMS,
            ).scalar()

    def _holder_pid(self):
        with self.observer.connect() as connection:
            return connection.execute(
                text(
                    'SELECT pid FROM pg_locks '
                    "WHERE locktype = 'advisory' "
                    'AND classid = :classid AND objid = :objid AND granted'
                ),
                LOCK_PARAMS,
            ).scalar()

    def _terminate_holder_backend(self):
        pid = self._holder_pid()
        with self.observer.connect() as connection:
            connection.execute(text('SELECT pg_terminate_backend(:pid)'), {'pid': pid})
        self._wait_until_released()

    def _wait_until_released(self, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._granted_locks() == 0:
                return
            time.sleep(0.1)
        raise AssertionError('scheduler lock was not released in time')

    def test_hold_is_exclusive(self):
        assert self.lock_a.hold() is True

        assert self.lock_b.hold() is False
        assert self._granted_locks() == 1

    def test_hold_confirms_leadership_without_reacquiring(self):
        assert self.lock_a.hold() is True
        assert self.lock_a.hold() is True

        assert self._granted_locks() == 1

    def test_release_frees_the_lock(self):
        self.lock_a.hold()

        self.lock_a.release()

        assert self._granted_locks() == 0
        assert self.lock_b.hold() is True

    def test_failover_when_leader_backend_is_terminated(self):
        assert self.lock_a.hold() is True

        self._terminate_holder_backend()

        assert self.lock_b.hold() is True  # takeover
        # the dead leader detects its lost connection without raising and
        # loses the reacquisition race
        assert self.lock_a.hold() is False

    def test_reacquires_after_own_connection_dies(self):
        assert self.lock_a.hold() is True

        self._terminate_holder_backend()

        assert self.lock_a.hold() is True  # fresh connection, immediate retake
        assert self._granted_locks() == 1
