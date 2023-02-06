# Copyright 2017-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from .. import helpers
from ... import exceptions


class QueryPaginator:
    _valid_directions = ['asc', 'desc']

    def __init__(self, column_map):
        self._column_map = column_map

    def update_query(
        self, query, limit=None, offset=None, order=None, direction=None, **ignored
    ):
        if order and direction:
            order_field = self._column_map.get(order)
            if not order_field:
                raise exceptions.InvalidSortColumnException(order)

            if direction not in self._valid_directions:
                raise exceptions.InvalidSortDirectionException(direction)

            order_clause = (
                order_field.asc() if direction == 'asc' else order_field.desc()
            )
            query = query.order_by(order_clause)

        if limit is not None:
            limit = self._check_valid_limit_or_offset(
                limit, None, exceptions.InvalidLimitException
            )
            query = query.limit(limit)

        if offset is not None:
            offset = self._check_valid_limit_or_offset(
                offset, 0, exceptions.InvalidOffsetException
            )
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


class PaginatorMixin:
    column_map = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._paginator = QueryPaginator(self.column_map)


class BaseDAO:
    _UNIQUE_CONSTRAINT_CODE = '23505'
    _FKEY_CONSTRAINT_CODE = '23503'

    @property
    def session(self):
        return helpers.get_db_session()
