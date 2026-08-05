# Copyright 2019-2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import time
from contextlib import contextmanager
from datetime import datetime, timedelta

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session as BaseSession
from sqlalchemy.orm import scoped_session, sessionmaker

logger = logging.getLogger(__name__)


Session = scoped_session(sessionmaker())

# wazo-auth shares its PostgreSQL database with other Wazo services and
# advisory lock keys are database-wide, so the two-int32 key form of
# pg_advisory_lock is used to namespace wazo-auth locks:
# - classid identifies wazo-auth: zlib.crc32(b'wazo-auth') & 0x7FFFFFFF
#   (hardcoded so the value is explicit and greppable in pg_locks)
# - objid identifies the lock within wazo-auth
ADVISORY_LOCK_CLASSID = 1073458317
STARTUP_LOCK_OBJID = 1
SCHEDULER_LOCK_OBJID = 2


def init_db(db_uri, pool_size=16, max_overflow=10):
    engine = create_engine(
        db_uri, pool_size=pool_size, max_overflow=max_overflow, pool_pre_ping=True
    )
    Session.configure(bind=engine)


def deinit_db():
    Session.get_bind().dispose()
    Session.remove()
    Session.configure(bind=None)


def get_db_session() -> BaseSession:
    return Session()


def commit_or_rollback():
    try:
        Session.commit()
    except Exception:
        Session.rollback()
        raise
    finally:
        Session.close()


@contextmanager
def db_session(read_only=True):
    """Context manager that ensures the session is properly committed or rolled back."""
    try:
        yield Session()
        if not read_only:
            Session.commit()
    except Exception:
        Session.rollback()
        raise
    finally:
        Session.remove()


@contextmanager
def db_ready(timeout):
    start_time = datetime.now()
    end_time = start_time + timedelta(seconds=timeout)
    while datetime.now() < end_time:
        try:
            ping_db()
        except Exception as e:
            logger.warning('fail to connect to the database: %s', e)
            time.sleep(0.5)
        else:
            yield
            return

    # Timeout expired, let it raise this time
    ping_db()


def ping_db():
    with get_db_session().get_bind().connect() as conn:
        conn.execute(text('SELECT 1'))


class StartupLockInterrupted(Exception):
    pass


class StartupLockTimeout(Exception):
    pass


STARTUP_LOCK_LOG_INTERVAL = 30

_STARTUP_LOCK_HOLDER_QUERY = (
    'SELECT a.pid, a.client_addr, a.application_name, '
    'now() - a.backend_start AS backend_age '
    'FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid '
    "WHERE l.locktype = 'advisory' "
    'AND l.classid = :classid AND l.objid = :objid AND l.granted'
)


def _describe_lock_holder(connection, params):
    # best effort: diagnostics must never break or mask the lock wait
    try:
        holder = connection.execute(text(_STARTUP_LOCK_HOLDER_QUERY), params).first()
    except Exception as e:
        return f'holder unknown: {e}'
    if holder is None:
        return 'holder unknown: no granted lock found'
    return (
        f'held by pid {holder.pid} from {holder.client_addr} '
        f'(application {holder.application_name!r}) '
        f'connected for {holder.backend_age}'
    )


@contextmanager
def startup_lock(engine, timeout, stop_event=None):
    """Serialize startup tasks across wazo-auth instances.

    Holds a PostgreSQL session-level advisory lock for the duration of the
    context, polling until it is acquired. Polling instead of a blocking
    pg_advisory_lock keeps the wait interruptible: Python defers signal
    handlers while blocked inside a libpq call, so a blocking wait would
    ignore SIGTERM until killed. When stop_event is given and gets set
    during the wait, StartupLockInterrupted is raised instead of running
    the body. While blocked, the lock holder (pid, client address, ...) is
    logged every STARTUP_LOCK_LOG_INTERVAL seconds so operators can see who
    is in the way; after timeout seconds StartupLockTimeout is raised so a
    hung holder cannot freeze startup forever. The lock connection uses
    AUTOCOMMIT so it never holds a transaction open while the caller works:
    an idle-in-transaction lock connection could be killed by
    idle_in_transaction_session_timeout, releasing the lock mid-work.
    """
    params = {'classid': ADVISORY_LOCK_CLASSID, 'objid': STARTUP_LOCK_OBJID}
    acquired = False
    connection = engine.connect().execution_options(isolation_level='AUTOCOMMIT')
    try:
        start_time = time.monotonic()
        deadline = start_time + timeout
        next_holder_log = start_time
        acquired = connection.execute(
            text('SELECT pg_try_advisory_lock(:classid, :objid)'), params
        ).scalar()
        while not acquired:
            now = time.monotonic()
            if now >= deadline:
                raise StartupLockTimeout(
                    f'could not acquire the wazo-auth startup lock '
                    f'within {timeout}s, {_describe_lock_holder(connection, params)}'
                )
            if now >= next_holder_log:
                logger.info(
                    'waiting for the wazo-auth startup lock (%.0fs elapsed), %s',
                    now - start_time,
                    _describe_lock_holder(connection, params),
                )
                next_holder_log = now + STARTUP_LOCK_LOG_INTERVAL
            if stop_event is None:
                time.sleep(2)
            elif stop_event.wait(2):
                raise StartupLockInterrupted()
            acquired = connection.execute(
                text('SELECT pg_try_advisory_lock(:classid, :objid)'), params
            ).scalar()
        yield
    finally:
        # Session-level advisory locks survive connection.close() because the
        # DBAPI connection goes back to the pool still holding them: unlock
        # explicitly, and drop the DBAPI connection if the unlock cannot be
        # issued (a dead connection has already released the lock server-side,
        # and any body exception must propagate unmasked).
        try:
            if acquired:
                connection.execute(
                    text('SELECT pg_advisory_unlock(:classid, :objid)'), params
                )
        except Exception:
            logger.warning(
                'could not release the wazo-auth startup lock, '
                'dropping its connection'
            )
            connection.invalidate()
        finally:
            connection.close()


class SchedulerLeaderLock:
    """Elect a single scheduler leader across wazo-auth instances.

    Non-blocking counterpart to startup_lock: the leader acquires a
    session-level advisory lock once and keeps its dedicated AUTOCOMMIT
    connection open across scheduler ticks, so its behavior is identical to
    a single process. PostgreSQL ties the lock to that connection: if the
    leader dies or its connection drops, the lock is released server-side
    and another instance can take over on its next tick.
    """

    _params = {'classid': ADVISORY_LOCK_CLASSID, 'objid': SCHEDULER_LOCK_OBJID}

    def __init__(self, engine):
        self._engine = engine
        self._connection = None

    def hold(self):
        """Acquire leadership or confirm it still holds; called every tick.

        Exceptions propagate so the caller decides how to survive a database
        outage; no half-open connection is kept behind.
        """
        if self._connection is not None:
            # a session-level advisory lock lives exactly as long as its
            # backend session: if this connection still answers, the lock is
            # still granted
            try:
                self._connection.execute(text('SELECT 1'))
                return True
            except Exception:
                logger.warning(
                    'lost the wazo-auth scheduler leader lock: '
                    'its connection died, dropping leadership'
                )
                self._connection.invalidate()
                self._connection.close()
                self._connection = None
                # the lock is free again server-side: fall through and try
                # to retake it on a fresh connection right away

        connection = self._engine.connect().execution_options(
            isolation_level='AUTOCOMMIT'
        )
        try:
            acquired = connection.execute(
                text('SELECT pg_try_advisory_lock(:classid, :objid)'), self._params
            ).scalar()
        except Exception:
            connection.invalidate()
            connection.close()
            raise
        if not acquired:
            connection.close()
            logger.debug('another wazo-auth instance holds the scheduler leader lock')
            return False
        self._connection = connection
        logger.info('acquired the wazo-auth scheduler leader lock')
        return True

    def release(self):
        if self._connection is None:
            return
        # see startup_lock: unlock explicitly so the lock does not leak into
        # the pool; drop the connection if the unlock cannot be issued (a
        # dead connection has already released the lock server-side)
        try:
            self._connection.execute(
                text('SELECT pg_advisory_unlock(:classid, :objid)'), self._params
            )
        except Exception:
            logger.warning(
                'could not release the wazo-auth scheduler leader lock, '
                'dropping its connection'
            )
            self._connection.invalidate()
        finally:
            self._connection.close()
            self._connection = None
