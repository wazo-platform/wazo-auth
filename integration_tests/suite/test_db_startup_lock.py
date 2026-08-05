# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import threading
import time
import unittest

from sqlalchemy import create_engine, text

from wazo_auth.database.helpers import (
    ADVISORY_LOCK_CLASSID,
    STARTUP_LOCK_OBJID,
    StartupLockTimeout,
    startup_lock,
)

from .helpers import base
from .helpers.constants import DB_URI

LOCK_PARAMS = {'classid': ADVISORY_LOCK_CLASSID, 'objid': STARTUP_LOCK_OBJID}


@base.use_asset('database')
class TestStartupLock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        port = base.DBAssetLaunchingTestCase.service_port(5432, 'postgres')
        uri = DB_URI.format(port=port)
        # pool_size=1/max_overflow=0 makes consecutive contexts reuse the same
        # DBAPI connection, which is what the leak test needs
        cls.engine = create_engine(uri, pool_size=1, max_overflow=0)
        cls.observer = create_engine(uri, isolation_level='AUTOCOMMIT')

    @classmethod
    def tearDownClass(cls):
        cls.observer.dispose()
        cls.engine.dispose()

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

    @staticmethod
    def _try_lock(connection):
        return connection.execute(
            text('SELECT pg_try_advisory_lock(:classid, :objid)'), LOCK_PARAMS
        ).scalar()

    @staticmethod
    def _unlock(connection):
        connection.execute(
            text('SELECT pg_advisory_unlock(:classid, :objid)'), LOCK_PARAMS
        )

    def test_lock_is_held_inside_context(self):
        with startup_lock(self.engine, timeout=10):
            with self.observer.connect() as connection:
                assert self._try_lock(connection) is False
            assert self._granted_locks() == 1

    def test_lock_is_released_on_exit(self):
        with startup_lock(self.engine, timeout=10):
            pass

        assert self._granted_locks() == 0

    def test_lock_is_released_after_exception(self):
        with self.assertRaises(RuntimeError):
            with startup_lock(self.engine, timeout=10):
                raise RuntimeError('boom')

        assert self._granted_locks() == 0

    def test_lock_is_not_leaked_through_pool_reuse(self):
        # a session-level advisory lock survives connection.close() when the
        # DBAPI connection returns to the pool: two consecutive contexts on a
        # single-connection pool prove the explicit unlock
        with startup_lock(self.engine, timeout=10):
            pass
        with startup_lock(self.engine, timeout=10):
            pass

        assert self._granted_locks() == 0

    def test_contended_acquisition_blocks_then_proceeds(self):
        events = []

        def enter_lock():
            with startup_lock(self.engine, timeout=10):
                events.append('entered')

        with self.observer.connect() as connection:
            assert self._try_lock(connection) is True
            try:
                thread = threading.Thread(target=enter_lock)
                thread.start()
                time.sleep(0.5)
                assert events == []  # still blocked on the held lock
            finally:
                self._unlock(connection)
            thread.join(timeout=10)

        assert events == ['entered']
        assert self._granted_locks() == 0

    def test_contended_acquisition_times_out_and_names_the_holder(self):
        with self.observer.connect() as connection:
            assert self._try_lock(connection) is True
            try:
                with self.assertRaises(StartupLockTimeout) as raised:
                    with startup_lock(self.engine, timeout=0):
                        raise AssertionError('the body must not run')
            finally:
                self._unlock(connection)

        assert 'held by pid' in str(raised.exception)
