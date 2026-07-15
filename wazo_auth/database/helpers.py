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


@contextmanager
def startup_lock(engine, stop_event=None):
    """Serialize startup tasks across wazo-auth instances.

    Holds a PostgreSQL session-level advisory lock for the duration of the
    context, polling until it is acquired. Polling instead of a blocking
    pg_advisory_lock keeps the wait interruptible: Python defers signal
    handlers while blocked inside a libpq call, so a blocking wait would
    ignore SIGTERM until killed. When stop_event is given and gets set
    during the wait, StartupLockInterrupted is raised instead of running
    the body. The lock connection uses AUTOCOMMIT so it never holds a
    transaction open while the caller works: an idle-in-transaction lock
    connection could be killed by idle_in_transaction_session_timeout,
    releasing the lock mid-work.
    """
    params = {'classid': ADVISORY_LOCK_CLASSID, 'objid': STARTUP_LOCK_OBJID}
    acquired = False
    connection = engine.connect().execution_options(isolation_level='AUTOCOMMIT')
    try:
        acquired = connection.execute(
            text('SELECT pg_try_advisory_lock(:classid, :objid)'), params
        ).scalar()
        if not acquired:
            logger.info(
                'waiting for the wazo-auth startup lock held by another instance'
            )
        while not acquired:
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
