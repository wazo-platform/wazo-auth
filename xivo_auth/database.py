# -*- coding: utf-8 -*-
#
# Copyright 2016-2017 The Wazo Authors  (see the AUTHORS file)
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

from contextlib import contextmanager
from itertools import izip
from threading import Lock
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
        token_data = token_payload.__dict__
        token_uuid = self._crud.create(token_data)
        return Token(token_uuid, **token_data)

    def remove_token(self, token_id):
        self._crud.delete(token_id)

    @classmethod
    def from_config(cls, config):
        crud = _TokenCRUD(config['db_uri'])
        return cls(crud)


class _TokenCRUD(object):

    _DELETE_TOKEN_QRY = """DELETE FROM auth_token WHERE uuid=%s;"""
    _INSERT_ACL_QRY = """\
INSERT INTO auth_acl (value, token_uuid)
VALUES """
    _INSERT_TOKEN_QRY = """\
INSERT INTO auth_token (auth_id, user_uuid, xivo_uuid, issued_t, expire_t)
VALUES (%s, %s, %s, %s, %s)
RETURNING uuid;
"""
    _SELECT_ACL_QRY = "SELECT value FROM auth_acl WHERE token_uuid=%s;"
    _SELECT_TOKEN_QRY = """\
SELECT uuid, auth_id, user_uuid, xivo_uuid, issued_t, expire_t
FROM auth_token
WHERE uuid=%s;
"""
    _RETURNED_COLUMNS = ['uuid', 'auth_id', 'xivo_user_uuid', 'xivo_uuid', 'issued_t', 'expire_t']

    def __init__(self, db_uri):
        self._db_uri = db_uri
        self._connection_lock = Lock()
        with self._connection_lock:
            self._conn = psycopg2.connect(self._db_uri)

    def create(self, body):
        token_args = (body['auth_id'], body['xivo_user_uuid'],
                      body['xivo_uuid'], int(body['issued_t']),
                      int(body['expire_t']))
        with self.connection() as conn:
            with conn.cursor() as curs:
                curs.execute(self._INSERT_TOKEN_QRY, token_args)
                token_uuid = curs.fetchone()[0]
                acls = body.get('acls')
                if acls:
                    values = ', '.join(curs.mogrify("(%s,%s)", (acl, token_uuid)) for acl in acls)
                    curs.execute(self._INSERT_ACL_QRY + values)
        return token_uuid

    def get(self, token_uuid):
        with self.connection() as conn:
            with conn.cursor() as curs:
                curs.execute(self._SELECT_TOKEN_QRY, (token_uuid,))
                row = curs.fetchone()
                if not row:
                    raise UnknownTokenException()
                curs.execute(self._SELECT_ACL_QRY, (row[0],))
                acls = [acl[0] for acl in curs.fetchall()]

        token_data = dict(izip(self._RETURNED_COLUMNS, row))
        token_data['acls'] = acls
        return token_data

    def delete(self, token_uuid):
        with self.connection() as conn:
            with conn.cursor() as curs:
                curs.execute(self._DELETE_TOKEN_QRY, (token_uuid,))

    @contextmanager
    def connection(self):
        with self._connection_lock:
            if self._conn.closed:
                self._conn = psycopg2.connect(self._db_uri)

            try:
                with self._conn.cursor() as curs:
                    curs.execute('SELECT 1;')
            except psycopg2.OperationalError:
                self._conn = psycopg2.connect(self._db_uri)

            yield self._conn
            self._conn.commit()
