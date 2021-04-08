# Copyright 2015-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import re
import time
import threading

from datetime import datetime

from xivo_bus.resources.auth.events import SessionDeletedEvent, SessionExpireSoonEvent

from wazo_auth.database.helpers import Session

logger = logging.getLogger(__name__)

DEFAULT_XIVO_UUID = os.getenv('XIVO_UUID')


class Token:
    def __init__(
        self,
        id_,
        auth_id,
        pbx_user_uuid,
        xivo_uuid,
        issued_t,
        expire_t,
        acl,
        metadata,
        session_uuid,
        user_agent,
        remote_addr,
        refresh_token=None,
    ):
        self.token = id_
        self.auth_id = auth_id
        self.pbx_user_uuid = pbx_user_uuid
        self.xivo_uuid = xivo_uuid
        self.issued_t = issued_t
        self.expire_t = expire_t
        self.acl = acl
        self.metadata = metadata
        self.session_uuid = session_uuid
        self.user_agent = user_agent
        self.remote_addr = remote_addr
        self.refresh_token = refresh_token

    def __eq__(self, other):
        return (
            self.token == other.token
            and self.auth_id == other.auth_id
            and self.pbx_user_uuid == other.pbx_user_uuid
            and self.xivo_uuid == other.xivo_uuid
            and self.issued_t == other.issued_t
            and self.expire_t == other.expire_t
            and self.acl == other.acl
            and self.metadata == other.metadata
            and self.session_uuid == other.session_uuid
            and self.user_agent == other.user_agent
            and self.remote_addr == other.remote_addr
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
        result = {
            'token': self.token,
            'auth_id': self.auth_id,
            'xivo_user_uuid': self.pbx_user_uuid,
            'xivo_uuid': self.xivo_uuid,
            'issued_at': self._format_local_time(self.issued_t),
            'expires_at': self._format_local_time(self.expire_t),
            'utc_issued_at': self._format_utc_time(self.issued_t),
            'utc_expires_at': self._format_utc_time(self.expire_t),
            'acl': self.acl,
            'metadata': self.metadata,
            'session_uuid': self.session_uuid,
            'remote_addr': self.remote_addr,
            'user_agent': self.user_agent,
        }
        if self.refresh_token:
            result['refresh_token'] = self.refresh_token
        return result

    def is_expired(self):
        return self.expire_t and time.time() > self.expire_t

    def matches_required_access(self, required_access):
        if required_access is None:
            return True

        positive_user_acl = set()
        negative_user_acl = set()

        for user_access in self.acl:
            if user_access.startswith('!'):
                negative_user_acl.add(user_access[1:])
            else:
                positive_user_acl.add(user_access)

        for negative_access in negative_user_acl:
            negative_access_regex = self._transform_access_to_regex(negative_access)
            if re.match(negative_access_regex, required_access):
                return False

        for positive_access in positive_user_acl:
            positive_access_regex = self._transform_access_to_regex(positive_access)
            if re.match(positive_access_regex, required_access):
                return True
        return False

    def _transform_access_to_regex(self, access):
        access_regex = re.escape(access)
        access_regex = access_regex.replace('\\*', '[^.]*?').replace('\\#', '.*?')
        access_regex = self._transform_access_me_to_uuid_or_me(access_regex)
        return re.compile('^{}$'.format(access_regex))

    def _transform_access_me_to_uuid_or_me(self, access_regex):
        access_regex = access_regex.replace(
            '\\.me\\.', '\\.(me|{auth_id})\\.'.format(auth_id=self.auth_id)
        )
        if access_regex.endswith('\\.me'):
            access_regex = '{access_start}\\.(me|{auth_id})'.format(
                access_start=access_regex[:-4],
                auth_id=self.auth_id,
            )
        return access_regex


class ExpiredTokenRemover:
    def __init__(self, config, dao, bus_publisher):
        self._dao = dao
        self._bus_publisher = bus_publisher
        self._cleanup_interval = config['token_cleanup_interval']
        self._debug = config['debug']

        self._tombstone = threading.Event()
        self._thread = threading.Thread(target=self._loop)
        self._thread.daemon = True

    def start(self):
        self._thread.start()

    def stop(self):
        self._tombstone.set()
        self._thread.join()
        self._tombstone.clear()

    def _loop(self):
        while not self._tombstone.is_set():
            started = time.monotonic()

            self._tokens_cleanup()
            self._tokens_notice()

            elapsed = time.monotonic() - started

            if elapsed >= self._cleanup_interval:
                log_level = logging.WARNING
            else:
                log_level = logging.DEBUG
            logger.log(log_level, "ExpiredTokenRemover tooks %s seconds", elapsed)

            if elapsed < self._cleanup_interval:
                self._tombstone.wait(self._cleanup_interval - elapsed)

    def _tokens_cleanup(self):
        try:
            tokens, sessions = self._dao.token.delete_expired_tokens_and_sessions()
            Session.commit()
        except Exception:
            Session.rollback()
            logger.warning(
                'failed to remove expired tokens and sessions', exc_info=self._debug
            )
            return
        finally:
            Session.close()

        self._publish_event(tokens, sessions, SessionDeletedEvent)

    def _tokens_notice(self):
        try:
            tokens, sessions = self._dao.token.get_tokens_and_session_that_expire_soon(
                self._cleanup_interval
            )
        except Exception:
            logger.warning(
                'failed to get tokens and sessions that expire soon',
                exc_info=self._debug,
            )
            return
        finally:
            Session.close()

        self._publish_event(tokens, sessions, SessionExpireSoonEvent)

    def _publish_event(self, tokens, sessions, event_class):
        for session in sessions:
            event_args = {
                'uuid': session['uuid'],
                'user_uuid': None,
                'tenant_uuid': None,
            }
            for token in tokens:
                if token['session_uuid'] == session['uuid']:
                    event_args['user_uuid'] = token['auth_id']
                    event_args['tenant_uuid'] = token['metadata'].get('tenant_uuid')
                    break
            else:
                logger.warning(
                    'session without token associated: {}'.format(session['uuid'])
                )

            self._bus_publisher.publish(event_class(**event_args))
