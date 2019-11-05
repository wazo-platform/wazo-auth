# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

Session = scoped_session(sessionmaker())


def init_db(db_uri, echo=False):
    engine = create_engine(db_uri, echo=echo, pool_pre_ping=True)
    Session.configure(bind=engine)


def get_dao_session():
    return Session()


@contextmanager
def session_scope():
    session = Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.remove()
