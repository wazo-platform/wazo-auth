# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from contextlib import contextmanager
from sqlalchemy import create_engine, or_, text
from sqlalchemy.orm import sessionmaker, scoped_session
from ... import exceptions


class QueryPaginator(object):

    _valid_directions = ['asc', 'desc']

    def __init__(self, column_map):
        self._column_map = column_map

    def update_query(self, query, limit=None, offset=None, order=None, direction=None, **ignored):
        if order and direction:
            order_field = self._column_map.get(order)
            if not order_field:
                raise exceptions.InvalidSortColumnException(order)

            if direction not in self._valid_directions:
                raise exceptions.InvalidSortDirectionException(direction)

            order_clause = order_field.asc() if direction == 'asc' else order_field.desc()
            query = query.order_by(order_clause)

        if limit is not None:
            limit = self._check_valid_limit_or_offset(limit, None, exceptions.InvalidLimitException)
            query = query.limit(limit)

        if offset is not None:
            offset = self._check_valid_limit_or_offset(offset, 0, exceptions.InvalidOffsetException)
            query = query.offset(offset)

        return query

    def _check_valid_limit_or_offset(self, value, default, exception):
        if value is True or value is False:
            raise exception(value)

        if value is None:
            return default

        try:
            value = int(value)
        except ValueError:
            raise exception(value)

        if value < 0:
            raise exception(value)

        return value


class PaginatorMixin(object):

    column_map = dict()

    def __init__(self, *args, **kwargs):
        super(PaginatorMixin, self).__init__(*args, **kwargs)
        self._paginator = QueryPaginator(self.column_map)


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
