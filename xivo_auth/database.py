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

from itertools import izip
from threading import Lock
import psycopg2
from .token import Token, UnknownTokenException
from .exceptions import DuplicatePolicyException, UnknownPolicyException


class Storage(object):

    def __init__(self, policy_crud, token_crud):
        self._policy_crud = policy_crud
        self._token_crud = token_crud

    def get_policy(self, policy_uuid):
        for policy in self._policy_crud.get(policy_uuid):
            return policy

    def get_token(self, token_id):
        token_data = self._token_crud.get(token_id)
        if not token_data:
            raise UnknownTokenException()

        id_ = token_data.pop('uuid')
        return Token(id_, **token_data)

    def create_policy(self, name, description, acl_templates):
        return self._policy_crud.create(name, description, acl_templates)

    def create_token(self, token_payload):
        token_data = token_payload.__dict__
        token_uuid = self._token_crud.create(token_data)
        return Token(token_uuid, **token_data)

    def delete_policy(self, policy_uuid):
        self._policy_crud.delete(policy_uuid)

    def list_policies(self):
        return self._policy_crud.get('%')

    def remove_token(self, token_id):
        self._token_crud.delete(token_id)

    @classmethod
    def from_config(cls, config):
        factory = _ConnectionFactory(config['db_uri'])
        policy_crud = _PolicyCRUD(factory)
        token_crud = _TokenCRUD(factory)
        return cls(policy_crud, token_crud)


class _CRUD(object):

    _UNIQUE_CONSTRAINT_CODE = '23505'

    def __init__(self, connection_factory):
        self._factory = connection_factory

    def connection(self):
        return self._factory.connection()

    @staticmethod
    def row_to_dict(columns, row):
        return dict(izip(columns, row))


class _PolicyCRUD(_CRUD):

    _DELETE_POLICY_QRY = "DELETE FROM auth_policy WHERE uuid=%s"
    _INSERT_TEMPLATE_QRY = "INSERT INTO auth_acl_template (template) VALUES (%s) RETURNING id"
    _INSERT_POLICY_TEMPLATE_QRY = "INSERT INTO auth_policy_template (policy_uuid, template_id) VALUES "
    _INSERT_POLICY_QRY = """\
INSERT INTO auth_policy (name, description)
VALUES (%s, %s)
RETURNING uuid
"""
    _SELECT_TEMPLATE_QRY = "SELECT id, template FROM auth_acl_template WHERE template in %s"
    _SELECT_POLICY_QRY = """\
SELECT auth_policy.uuid,
       auth_policy.name,
       auth_policy.description,
       array_agg(auth_acl_template.template) AS acl_templates
FROM auth_policy
LEFT JOIN auth_policy_template ON auth_policy.uuid = auth_policy_template.policy_uuid
LEFT JOIN auth_acl_template ON auth_policy_template.template_id = auth_acl_template.id
WHERE auth_policy.uuid LIKE %s
GROUP BY auth_policy.uuid, auth_policy.name, auth_policy.description;
"""
    _RETURNED_COLUMNS = ['uuid', 'name', 'description', 'acl_templates']

    def create(self, name, description, acl_templates):
        with self.connection().cursor() as curs:
            template_ids = self._create_or_find_acl_templates(curs, acl_templates)
            try:
                curs.execute(self._INSERT_POLICY_QRY, (name, description))
            except psycopg2.IntegrityError as e:
                if e.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    raise DuplicatePolicyException(name)
                raise
            uuid = curs.fetchone()[0]
            if template_ids:
                values = ', '.join(curs.mogrify("(%s,%s)", (uuid, id_)) for id_ in template_ids)
                curs.execute(self._INSERT_POLICY_TEMPLATE_QRY + values)
        return uuid

    def delete(self, policy_uuid):
        with self.connection().cursor() as curs:
            curs.execute(self._DELETE_POLICY_QRY, (policy_uuid,))
            if curs.rowcount == 0:
                raise UnknownPolicyException()

    def get(self, policy_uuid):
        with self.connection().cursor() as curs:
            curs.execute(self._SELECT_POLICY_QRY, (policy_uuid,))
            rows = curs.fetchall()

        if not rows:
            raise UnknownPolicyException()

        policies = []
        for row in rows:
            policy = self.row_to_dict(self._RETURNED_COLUMNS, row)

            # The array_agg function returns [None] if there no acl_template
            if policy['acl_templates'] == [None]:
                policy['acl_templates'] = []

            policies.append(policy)

        return policies

    def _create_or_find_acl_templates(self, curs, acl_templates):
        if not acl_templates:
            return []

        curs.execute(self._SELECT_TEMPLATE_QRY, (tuple(acl_templates),))
        existing = {row[1]: row[0] for row in curs.fetchall()}
        for template in acl_templates:
            if template in existing:
                continue
            id_ = self._insert_acl_template(curs, template)
            existing[template] = id_
        return existing.values()

    def _insert_acl_template(self, curs, template):
        curs.execute(self._INSERT_TEMPLATE_QRY, (template,))
        return curs.fetchone()[0]


class _TokenCRUD(_CRUD):

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

    def create(self, body):
        token_args = (body['auth_id'], body['xivo_user_uuid'],
                      body['xivo_uuid'], int(body['issued_t']),
                      int(body['expire_t']))
        with self.connection().cursor() as curs:
            curs.execute(self._INSERT_TOKEN_QRY, token_args)
            token_uuid = curs.fetchone()[0]
            acls = body.get('acls')
            if acls:
                values = ', '.join(curs.mogrify("(%s,%s)", (acl, token_uuid)) for acl in acls)
                curs.execute(self._INSERT_ACL_QRY + values)
        return token_uuid

    def get(self, token_uuid):
        with self.connection().cursor() as curs:
            curs.execute(self._SELECT_TOKEN_QRY, (token_uuid,))
            row = curs.fetchone()
            if not row:
                raise UnknownTokenException()
            curs.execute(self._SELECT_ACL_QRY, (row[0],))
            acls = [acl[0] for acl in curs.fetchall()]

        token_data = self.row_to_dict(self._RETURNED_COLUMNS, row)
        token_data['acls'] = acls
        return token_data

    def delete(self, token_uuid):
        with self.connection().cursor() as curs:
            curs.execute(self._DELETE_TOKEN_QRY, (token_uuid,))


class _ConnectionFactory(object):

    def __init__(self, db_uri):
        self._db_uri = db_uri
        self._connection_lock = Lock()
        self._conn = self._new_connection()

    def _new_connection(self):
        conn = psycopg2.connect(self._db_uri)
        conn.autocommit = True
        return conn

    def connection(self):
        with self._connection_lock:
            if self._conn.closed:
                self._conn = self._new_connection()

            try:
                with self._conn.cursor() as curs:
                    curs.execute('SELECT 1;')
            except psycopg2.OperationalError:
                self._conn = self._new_connection()

            return self._conn
