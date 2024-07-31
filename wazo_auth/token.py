# Copyright 2015-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import threading
import time
from datetime import datetime

from wazo_bus.resources.auth.events import SessionDeletedEvent, SessionExpireSoonEvent
from xivo.auth_verifier import AccessCheck

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
        refresh_token_uuid=None,
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
        self.refresh_token_uuid = refresh_token_uuid
        self._access_check = AccessCheck(self.auth_id, self.session_uuid, self.acl)

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
        return self._access_check.matches_required_access(required_access)


class ExpiredTokenRemover:
    def __init__(self, config, dao, bus_publisher, saml_service):
        self._dao = dao
        self._bus_publisher = bus_publisher
        self._cleanup_interval = config['token_cleanup_interval']
        self._batch_size = config['token_cleanup_batch_size']
        self._debug = config['debug']
        if self._cleanup_interval < 1:
            return

        self._tombstone = threading.Event()
        self._thread = threading.Thread(target=self._loop)
        self._thread.daemon = True
        self._saml_service = saml_service

    def start(self):
        if self._cleanup_interval > 0:
            self._thread.start()

    def stop(self):
        if self._cleanup_interval > 0:
            self._tombstone.set()
            self._thread.join()
            self._tombstone.clear()

    def _loop(self):
        while not self._tombstone.is_set():
            started = time.monotonic()

            try:
                self._purge_expired_sessions()
                self._purge_expired_saml_sessions()
                self._notify_expire_soon()
            except Exception:
                logger.warning(
                    '%s: an exception occured during execution',
                    self.__class__.__name__,
                    exc_info=self._debug,
                )
                Session.close()

            elapsed = time.monotonic() - started

            if elapsed >= self._cleanup_interval:
                log_level = logging.WARNING
            else:
                log_level = logging.DEBUG
            logger.log(log_level, "ExpiredTokenRemover took %.5f seconds", elapsed)

            if elapsed < self._cleanup_interval:
                self._tombstone.wait(self._cleanup_interval - elapsed)

    def _notify_expire_soon(self):
        generator = self._dao.token.get_tokens_and_sessions_about_to_expire(
            self._cleanup_interval, self._batch_size
        )
        try:
            for tokens, sessions in generator:
                self._publish_events(SessionExpireSoonEvent, tokens, sessions)
        finally:
            Session.close()

    def _purge_expired_sessions(self):
        try:
            for tokens, sessions in self._dao.token.purge_expired_tokens_and_sessions(
                self._batch_size
            ):
                try:
                    Session.commit()
                except Exception:
                    Session.rollback()
                    logger.warning(
                        'failed to remove expired tokens and sessions',
                        exc_info=self._debug,
                    )
                    raise

                self._publish_events(SessionDeletedEvent, tokens, sessions)
        finally:
            Session.close()

    def _purge_expired_saml_sessions(self):
        self._saml_service.clean_pending_requests()

    def _publish_events(self, event_class, tokens, sessions):
        for token, session in zip(tokens, sessions):
            if token['session_uuid'] != session['uuid']:
                logger.warning('token and session mistmatch')
                continue

            if 'tenant_uuid' not in token['metadata']:
                logger.warning(
                    'invalid session %s: no tenant_uuid found', session['uuid']
                )
                continue

            event = event_class(
                session_uuid=session['uuid'],
                tenant_uuid=token['metadata']['tenant_uuid'],
                user_uuid=token['auth_id'],
            )
            self._bus_publisher.publish(event)
