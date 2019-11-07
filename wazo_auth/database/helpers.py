# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

Session = scoped_session(sessionmaker())


def init_db(db_uri):
    engine = create_engine(db_uri, pool_pre_ping=True)
    Session.configure(bind=engine)


def deinit_db():
    Session.get_bind().dispose()
    Session.remove()
    Session.configure(bind=None)


@contextmanager
def new_session():
    session = Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
