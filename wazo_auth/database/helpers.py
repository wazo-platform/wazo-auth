# Copyright 2019-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import time

from contextlib import contextmanager
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

logger = logging.getLogger(__name__)


Session = scoped_session(sessionmaker())

DEFAULT_POOL_SIZE = 5


def init_db(db_uri, max_connections=15):
    max_overflow = max_connections - DEFAULT_POOL_SIZE
    max_overflow = 10 if max_overflow < 10 else max_overflow
    engine = create_engine(db_uri, max_overflow=max_overflow, pool_pre_ping=True)
    Session.configure(bind=engine)


def deinit_db():
    Session.get_bind().dispose()
    Session.remove()
    Session.configure(bind=None)


def get_db_session():
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
    get_db_session().get_bind().execute('SELECT 1')
