# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

import sqlalchemy as sa

logger = logging.getLogger(__name__)


class Database:
    @classmethod
    def build(cls, user, password, host, port, db):
        uri = f"postgresql://{user}:{password}@{host}:{port}"
        return cls(uri, db)

    def __init__(self, uri, db):
        self.uri = uri
        self.db = db
        self._engine = self.create_engine()

    def is_up(self):
        try:
            self.connect()
            return True
        except Exception as e:
            logger.debug('Database is down: %s', e)
            return False

    def create_engine(self, db=None, isolate=False):
        db = db or self.db
        uri = f"{self.uri}/{db}"
        if isolate:
            return sa.create_engine(uri, isolation_level='AUTOCOMMIT')
        return sa.create_engine(uri)

    def connect(self, db=None):
        return self._engine.connect()

    def inject_sql(self, sql):
        with self.connect() as connection:
            return connection.execute(sql)

    def current_summary(self):
        query = sa.text(
            "SELECT tablename FROM pg_catalog.pg_tables "
            "WHERE schemaname != 'pg_catalog' AND schemaname != 'information_schema';"
        )
        with self.connect() as connection:
            result = connection.execute(query)
            table_names = {row.tablename for row in result}
            tables_counts = {
                table_name: self._count_table_rows(connection, table_name)
                for table_name in table_names
            }
        return DBSummary(tables_counts)

    def _count_table_rows(self, connection, table_name: str) -> int:
        query = sa.text(f"SELECT COUNT(*) FROM {table_name};")
        count = connection.execute(query).scalar()
        return count


class DBSummary:
    def __init__(self, tables):
        self._tables = tables

    def diff(self, other_summary):
        '''Returns current summary minus another summary'''
        left = self._tables
        right = other_summary._tables
        diff = {
            table_name: left[table_name] - right[table_name]
            for table_name in set(left) | set(right)
            if left.get(table_name) != right.get(table_name)
        }
        return DBSummary(diff)

    def __mul__(self, multiplier):
        return DBSummary(
            {
                table_name: value * multiplier
                for table_name, value in self._tables.items()
            }
        )

    def __eq__(self, other):
        return self._tables == other._tables

    def __repr__(self):
        return repr(self._tables)

    def __str__(self):
        return str(self._tables)

    def __len__(self):
        return len(self._tables)
