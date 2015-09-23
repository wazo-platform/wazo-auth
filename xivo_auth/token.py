# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Avencall
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
import socket

from unidecode import unidecode
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

    def __init__(self, token, auth_id, xivo_user_uuid, now_, later_, acls):
        self.token = token
        self.auth_id = auth_id
        self.xivo_user_uuid = xivo_user_uuid
        self.issued_at = now_
        self.expires_at = later_
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
        return now() > self.expires_at

    def matches_required_acl(self, required_acl):
        # TODO: add pattern matching
        return required_acl is None or required_acl in self.acls

    @classmethod
    def from_consul(cls, d):
        acls = d.get('acls', {}) or {}

        return Token(d['token'], d['auth_id'], d['xivo_user_uuid'],
                     d['issued_at'], d['expires_at'], acls.keys())

    @classmethod
    def from_dict(cls, d):
        return Token(d['token'], d['auth_id'], d['xivo_user_uuid'],
                     d['issued_at'], d['expires_at'], d['acls'] or [])


class Manager(object):

    consul_token_kv = 'xivo/xivo-auth/tokens/{}'

    def __init__(self, config, consul, celery, consul_acl_generator=None):
        self._consul_acl_generator = consul_acl_generator or _ConsulACLGenerator()
        self._default_expiration = config['default_token_lifetime']
        self._consul = consul
        self._celery = celery

    def new_token(self, backend, login, args):
        from xivo_auth import tasks

        auth_id, xivo_user_uuid = backend.get_ids(login, args)
        rules = self._consul_acl_generator.create_from_backend(backend, login, args)
        acls = backend.get_acls(login, args)
        try:
            consul_token = self._consul.acl.create(rules=rules)
        except ConnectionError:
            raise _ConsulConnectionException()

        expiration = args.get('expiration', self._default_expiration)
        token = Token(consul_token, auth_id, xivo_user_uuid, now(), later(expiration), acls)
        task_id = self._get_token_hash(token)
        self._push_token_data(token)
        try:
            tasks.clean_token.apply_async(args=[consul_token], countdown=expiration, task_id=task_id)
        except socket.error:
            raise _RabbitMQConnectionException()
        return token

    def remove_token(self, token):
        task_id = self._get_token_hash(token)
        try:
            self._celery.control.revoke(task_id)
        except socket.error:
            raise _RabbitMQConnectionException()
        self.remove_expired_token(token)

    def remove_expired_token(self, token):
        try:
            self._consul.acl.destroy(token)
            self._consul.kv.delete('xivo/xivo-auth/tokens/{}'.format(token), recurse=True)
        except ConnectionError:
            raise _ConsulConnectionException()

    def get(self, consul_token, required_acl):
        try:
            key = self.consul_token_kv.format(consul_token)
            index, values = self._consul.kv.get(key, recurse=True)
        except ConnectionError:
            raise _ConsulConnectionException()

        if not values:
            raise UnknownTokenException()

        token = Token.from_consul(values_to_dict(values)['xivo']['xivo-auth']['tokens'][consul_token])

        if token.is_expired():
            raise UnknownTokenException()

        if not token.matches_required_acl(required_acl):
            raise MissingACLTokenException(required_acl)

        return token

    def _push_token_data(self, token):
        flat_dict = FlatDict({'xivo': {'xivo-auth': {'tokens': {token.token: token.to_consul()}}}})
        try:
            for key, value in flat_dict.iteritems():
                self._consul.kv.put(key, value)
        except ConnectionError:
            raise _ConsulConnectionException()

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
