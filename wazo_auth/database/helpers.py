# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from xivo import sqlalchemy_helper

Session = scoped_session(sessionmaker())


def init_db(db_uri, echo=False):
    engine = create_engine(db_uri, echo=echo)
    Session.configure(bind=engine)
    sqlalchemy_helper.handle_db_restart()


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
        Session.remove()
