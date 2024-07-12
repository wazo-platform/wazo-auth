# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


import sqlalchemy.types as types


class XMLPostgresqlType(types.UserDefinedType):
    def get_col_spec(self, **kw):
        return "XML"

    def bind_processor(self, dialect):
        def process(value):
            return value

        return process

    def result_processor(self, dialect, coltype):
        def process(value):
            return value

        return process
