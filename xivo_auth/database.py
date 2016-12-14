# -*- coding: utf-8 -*-
#
# Copyright 2016 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>

from itertools import izip

import psycopg2

from .token import Token, UnknownTokenException


class Storage(object):

    def __init__(self, crud):
        self._crud = crud

    def get_token(self, token_id):
        token_data = self._crud.get(token_id)
        if not token_data:
            raise UnknownTokenException()

        id_ = token_data.pop('uuid')
        return Token(id_, **token_data)

    def create_token(self, token_payload):
        token_uuid = self._crud.create(token_payload)
        return Token(token_uuid, **token_payload.__dict__)

    def remove_token(self, token_id):
        self._crud.delete(token_id)

    @classmethod
    def from_config(cls, config):
        pass


class _TokenCRUD(object):

    _DELETE_TOKEN_QRY = """DELETE FROM auth_token WHERE uuid=%s;"""
    _INSERT_TOKEN_QRY = """\
INSERT INTO auth_token (auth_id, user_uuid, xivo_uuid, issued_t, expire_t)
VALUES (%s, %s, %s, %s, %s)
RETURNING uuid;
"""
    _SELECT_TOKEN_QRY = """\
SELECT uuid, auth_id, user_uuid, xivo_uuid, issued_t, expire_t
FROM auth_token
WHERE uuid=%s;
"""
    _RETURNED_COLUMNS = ['uuid', 'auth_id', 'xivo_user_uuid', 'xivo_uuid', 'issued_t', 'expire_t']

    def __init__(self, db_uri):
        self._db_uri = db_uri
        self._conn = psycopg2.connect(self._db_uri)

    def create(self, body):
        token_args = (body['auth_id'], body['xivo_user_uuid'],
                      body['xivo_uuid'], int(body['issued_t']),
                      int(body['expire_t']))
        with self._conn.cursor() as curs:
            curs.execute(self._INSERT_TOKEN_QRY, token_args)
            token_uuid = curs.fetchone()[0]
        return token_uuid

    def get(self, token_uuid):
        with self._conn.cursor() as curs:
            curs.execute(self._SELECT_TOKEN_QRY, (token_uuid,))
            row = curs.fetchone()

        if not row:
            raise UnknownTokenException()

        return dict(izip(self._RETURNED_COLUMNS, row))

    def delete(self, token_uuid):
        with self._conn.cursor() as curs:
            curs.execute(self._DELETE_TOKEN_QRY, (token_uuid,))
