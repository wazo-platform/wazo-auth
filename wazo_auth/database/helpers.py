# Copyright 2019-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

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
