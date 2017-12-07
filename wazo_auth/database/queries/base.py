# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from contextlib import contextmanager
from sqlalchemy import create_engine, or_, text
from sqlalchemy.orm import sessionmaker, scoped_session


class SearchFilter(object):

    def __init__(self, *columns):
        self._columns = columns

    def new_filter(self, search=None, **ignored):
        if search is None:
            return text('true')

        if not search:
            pattern = '%'
        else:
            words = [w for w in search.split(' ') if w]
            pattern = '%{}%'.format('%'.join(words))

        return or_(column.ilike(pattern) for column in self._columns)


class BaseDAO(object):

    _UNIQUE_CONSTRAINT_CODE = '23505'
    _FKEY_CONSTRAINT_CODE = '23503'
    search_filter = SearchFilter()

    def __init__(self, db_uri):
        self._Session = scoped_session(sessionmaker())
        engine = create_engine(db_uri)
        self._Session.configure(bind=engine)

    @contextmanager
    def new_session(self):
        session = self._Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            self._Session.remove()

    @classmethod
    def new_search_filter(cls, **kwargs):
        return cls.search_filter.new_filter(**kwargs)
