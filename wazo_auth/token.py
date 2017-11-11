# -*- coding: utf-8 -*-
#
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
#
# SPDX-License-Identifier: GPL-3.0+

import hashlib
import logging
import os
import re
import time
from threading import Timer

from uuid import uuid4
from datetime import datetime

from .exceptions import (
    MissingACLTokenException,
    UnknownPolicyException,
    UnknownTokenException,
)


logger = logging.getLogger(__name__)

DEFAULT_XIVO_UUID = os.getenv('XIVO_UUID')


class Token(object):

    def __init__(self, id_, auth_id, xivo_user_uuid, xivo_uuid, issued_t, expire_t, acls):
        self.token = id_
        self.auth_id = auth_id
        self.xivo_user_uuid = xivo_user_uuid
        self.xivo_uuid = xivo_uuid
        self.issued_t = issued_t
        self.expire_t = expire_t
        self.acls = acls

    def __eq__(self, other):
        return (
            self.token == other.token
            and self.auth_id == other.auth_id
            and self.xivo_user_uuid == other.xivo_user_uuid
            and self.xivo_uuid == other.xivo_uuid
            and self.issued_t == other.issued_t
            and self.expire_t == other.expire_t
            and self.acls == other.acls
        )

    def __ne__(self, other):
        return not self == other

    @staticmethod
    def _format_local_time(t):
        if not t:
            return None
        return datetime.fromtimestamp(t).isoformat()

    @staticmethod
    def _format_utc_time(t):
        if not t:
            return None
        return datetime.utcfromtimestamp(t).isoformat()

    def to_dict(self):
        return {'token': self.token,
                'auth_id': self.auth_id,
                'xivo_user_uuid': self.xivo_user_uuid,
                'xivo_uuid': self.xivo_uuid,
                'issued_at': self._format_local_time(self.issued_t),
                'expires_at': self._format_local_time(self.expire_t),
                'utc_issued_at': self._format_utc_time(self.issued_t),
                'utc_expires_at': self._format_utc_time(self.expire_t),
                'acls': self.acls}

    def is_expired(self):
        return self.expire_t and time.time() > self.expire_t

    def matches_required_acl(self, required_acl):
        if required_acl is None:
            return True

        for user_acl in self.acls:
            user_acl_regex = self._transform_acl_to_regex(user_acl)
            if re.match(user_acl_regex, required_acl):
                return True
        return False

    def _transform_acl_to_regex(self, acl):
        acl_regex = re.escape(acl).replace('\*', '[^.]*?').replace('\#', '.*?')
        acl_regex = self._transform_acl_me_to_uuid_or_me(acl_regex)
        return re.compile('^{}$'.format(acl_regex))

    def _transform_acl_me_to_uuid_or_me(self, acl_regex):
        acl_regex = acl_regex.replace('\.me\.', '\.(me|{auth_id})\.'.format(auth_id=self.auth_id))
        if acl_regex.endswith('\.me'):
            acl_regex = '{acl_start}\.(me|{auth_id})'.format(acl_start=acl_regex[:-4], auth_id=self.auth_id)
        return acl_regex

    @classmethod
    def from_payload(cls, payload):
        id_ = str(uuid4())
        return Token(
            id_,
            auth_id=payload.auth_id,
            xivo_user_uuid=payload.xivo_user_uuid,
            xivo_uuid=payload.xivo_uuid,
            issued_t=payload.issued_t,
            expire_t=payload.expire_t,
            acls=payload.acls)


class TokenPayload(object):

    def __init__(self, auth_id, xivo_user_uuid, xivo_uuid, issued_t, expire_t, acls):
        self.auth_id = auth_id
        self.xivo_user_uuid = xivo_user_uuid
        self.xivo_uuid = xivo_uuid
        self.issued_t = issued_t
        self.expire_t = expire_t
        self.acls = acls or []


class ExpiredTokenRemover(object):

    def __init__(self, config, dao):
        self._dao = dao
        self._cleanup_interval = config['token_cleanup_interval']
        self._debug = config['debug']

    def run(self):
        self._cleanup()
        self._reschedule(self._cleanup_interval)

    def _cleanup(self):
        try:
            self._dao.remove_expired_tokens()
        except Exception:
            logger.warning('failed to remove expired tokens', exc_info=self._debug)

    def _reschedule(self, interval):
        t = Timer(interval, self.run)
        t.daemon = True
        t.start()


class Manager(object):

    def __init__(self, config, dao):
        self._backend_policies = config.get('backend_policies', {})
        self._default_expiration = config['default_token_lifetime']
        self._dao = dao

    def new_token(self, backend, login, args):
        auth_id, xivo_user_uuid = backend.get_ids(login, args)
        xivo_uuid = backend.get_xivo_uuid(args)
        args['acl_templates'] = self._get_acl_templates(args['backend'])
        acls = backend.get_acls(login, args)
        expiration = args.get('expiration', self._default_expiration)
        t = time.time()
        token_payload = TokenPayload(
            auth_id=auth_id,
            xivo_user_uuid=xivo_user_uuid,
            xivo_uuid=xivo_uuid,
            expire_t=t + expiration,
            issued_t=t,
            acls=acls)

        token = self._dao.create_token(token_payload)

        return token

    def remove_token(self, token):
        self._dao.remove_token(token)

    def get(self, token_uuid, required_acl):
        token = self._dao.get_token(token_uuid)

        if token.is_expired():
            raise UnknownTokenException()

        if not token.matches_required_acl(required_acl):
            raise MissingACLTokenException(required_acl)

        return token

    def _get_acl_templates(self, backend_name):
        policy_name = self._backend_policies.get(backend_name)
        if not policy_name:
            return []

        matching_policies = self._dao.policy.get(name=policy_name, limit=1)
        for policy in matching_policies:
            return policy['acl_templates']

        logger.info('Unknown policy name "%s" configured for backend "%s"', policy_name, backend_name)
        return []

    def _get_token_hash(self, token):
        return hashlib.sha256('{token}'.format(token=token)).hexdigest()
