# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Avencall
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import hashlib
import json
import logging
import re
import socket
import urllib

from unidecode import unidecode
from uuid import UUID
from requests.exceptions import ConnectionError

from xivo_auth.helpers import now, later, values_to_dict, FlatDict

logger = logging.getLogger(__name__)


class ManagerException(Exception):
    pass


class UnknownTokenException(ManagerException):

    code = 404

    def __str__(self):
        return 'No such token'


class MissingACLTokenException(ManagerException):

    code = 403

    def __init__(self, required_acl):
        super(MissingACLTokenException, self).__init__()
        self._required_acl = required_acl

    def __str__(self):
        return 'Unauthorized for {}'.format(unidecode(self._required_acl))


class _ConsulConnectionException(ManagerException):

    code = 500

    def __str__(self):
        return 'Connection to consul failed'


class _RabbitMQConnectionException(ManagerException):

    code = 500

    def __str__(self):
        return 'Connection to rabbitmq failed'


class Token(object):

    def __init__(self, id_, auth_id, xivo_user_uuid, issued_at, expires_at, acls):
        self.token = id_
        self.auth_id = auth_id
        self.xivo_user_uuid = xivo_user_uuid
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.acls = acls

    def to_consul(self):
        acls = {acl: acl for acl in self.acls}
        return {'token': self.token,
                'auth_id': self.auth_id,
                'xivo_user_uuid': self.xivo_user_uuid,
                'issued_at': self.issued_at,
                'expires_at': self.expires_at,
                'acls': acls or None}

    def to_dict(self):
        return {'token': self.token,
                'auth_id': self.auth_id,
                'xivo_user_uuid': self.xivo_user_uuid,
                'issued_at': self.issued_at,
                'expires_at': self.expires_at,
                'acls': self.acls}

    def is_expired(self):
        return self.expires_at and now() > self.expires_at

    def matches_required_acl(self, required_acl):
        if required_acl is None:
            return True

        for user_acl in self.acls:
            if user_acl.endswith('.me'):
                user_acl = '{}.{}'.format(user_acl[:-3], self.auth_id)
            else:
                user_acl = user_acl.replace('.me.', '.{}.'.format(self.auth_id))

            user_acl_regex = self._transform_acl_to_regex(user_acl)
            if re.match(user_acl_regex, required_acl):
                return True
        return False

    def _transform_acl_to_regex(self, acl):
        acl_regex = re.escape(acl).replace('\*', '[^.]*?').replace('\#', '.*?')
        return re.compile('^{}$'.format(acl_regex))

    @classmethod
    def from_consul(cls, d):
        acls = d.get('acls', {}) or {}
        return Token(d['token'], d['auth_id'], d['xivo_user_uuid'],
                     d['issued_at'], d['expires_at'], acls.keys())

    @classmethod
    def from_payload(cls, id_, payload):
        return Token(id_, payload.auth_id, payload.xivo_user_uuid,
                     payload.issued_at, payload.expires_at, payload.acls)


class TokenPayload(object):

    def __init__(self, auth_id, xivo_user_uuid=None, issued_at=None, expires_at=None, acls=None):
        if not issued_at:
            issued_at = now()
        if not acls:
            acls = []
        self.auth_id = auth_id
        self.xivo_user_uuid = xivo_user_uuid
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.acls = acls


class Manager(object):

    def __init__(self, config, storage, celery, consul_acl_generator=None):
        self._consul_acl_generator = consul_acl_generator or _ConsulACLGenerator()
        self._default_expiration = config['default_token_lifetime']
        self._storage = storage
        self._celery = celery

    def new_token(self, backend, login, args):
        from xivo_auth import tasks

        auth_id, xivo_user_uuid = backend.get_ids(login, args)
        rules = self._consul_acl_generator.create_from_backend(backend, login, args)
        acls = backend.get_acls(login, args)
        expiration = args.get('expiration', self._default_expiration)
        token_payload = TokenPayload(auth_id=auth_id, xivo_user_uuid=xivo_user_uuid,
                                     expires_at=later(expiration), acls=acls)

        token = self._storage.create_token(token_payload, rules)

        task_id = self._get_token_hash(token)
        try:
            tasks.clean_token.apply_async(args=[token.token], countdown=expiration, task_id=task_id)
        except socket.error:
            raise _RabbitMQConnectionException()
        return token

    def remove_token(self, token):
        task_id = self._get_token_hash(token)
        try:
            self._celery.control.revoke(task_id)
        except socket.error:
            raise _RabbitMQConnectionException()
        self._storage.remove_token(token)

    def remove_expired_token(self, token):
        self._storage.remove_token(token)

    def get(self, consul_token, required_acl):
        token = self._storage.get_token(consul_token)

        if token.is_expired():
            raise UnknownTokenException()

        if not token.matches_required_acl(required_acl):
            raise MissingACLTokenException(required_acl)

        return token

    def _get_token_hash(self, token):
        return hashlib.sha256('{token}'.format(token=token)).hexdigest()


class _ConsulACLGenerator(object):

    def create_from_backend(self, backend, login, args):
        backend_specific_acls = backend.get_consul_acls(login, args)
        return self.create(backend_specific_acls)

    def create(self, acls):
        rules = {'key': {'': {'policy': 'deny'}}}
        for rule_policy in acls:
            rules['key'][rule_policy['rule']] = {'policy': rule_policy['policy']}

        return json.dumps(rules)


class Storage(object):

    _TOKEN_KEY_FORMAT = 'xivo/xivo-auth/tokens/{}'

    def __init__(self, consul):
        self._consul = consul

    def get_token(self, token_id):
        self._check_valid_token_id(token_id)

        key = self._TOKEN_KEY_FORMAT.format(token_id)
        try:
            _, values = self._consul.kv.get(key, recurse=True)
        except ConnectionError as e:
            logger.error('Connection to consul failed: %s', e)
            raise _ConsulConnectionException()

        if not values:
            raise UnknownTokenException()

        return Token.from_consul(values_to_dict(values)['xivo']['xivo-auth']['tokens'][token_id])

    def create_token(self, token_payload, rules):
        try:
            token_id = self._consul.acl.create(rules=rules)
            token = Token.from_payload(token_id, token_payload)
            self._store_token(token)
        except ConnectionError as e:
            logger.error('Connection to consul failed: %s', e)
            raise _ConsulConnectionException()
        return token

    def remove_token(self, token_id):
        self._check_valid_token_id(token_id)

        try:
            self._consul.acl.destroy(token_id)
            self._consul.kv.delete(self._TOKEN_KEY_FORMAT.format(token_id), recurse=True)
        except ConnectionError as e:
            logger.error('Connection to consul failed: %s', e)
            raise _ConsulConnectionException()

    def _store_token(self, token):
        flat_dict = FlatDict({'xivo': {'xivo-auth': {'tokens': {token.token: token.to_consul()}}}})
        for key, value in flat_dict.iteritems():
            value = self._ensure_bytes_type(value)
            self._consul.kv.put(urllib.quote(key), value)

    def _ensure_bytes_type(self, value):
        if isinstance(value, unicode):
            return value.encode('utf-8')
        return value

    def _check_valid_token_id(self, token_id):
        try:
            UUID(hex=token_id)
        except ValueError as e:
            logger.warning('Invalid token ID: %s', e)
            raise UnknownTokenException()
