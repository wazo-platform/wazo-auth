# Copyright 2015-2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import time
import unittest
import uuid
from unittest.mock import Mock, call, patch

import pytest

from wazo_auth import token
from wazo_auth.token import ExpiredTokenRemover


def new_uuid():
    return str(uuid.uuid4())


class TestToken(unittest.TestCase):
    def setUp(self):
        self.id_ = new_uuid()
        self.auth_id = 'the-auth-id'
        self.pbx_user_uuid = new_uuid()
        self.xivo_uuid = new_uuid()
        self.session_uuid = new_uuid()
        self.issued_at = 1480011471.53537
        self.expires_at = 1480011513.53537
        self.acl = ['confd']
        self.metadata = {
            'uuid': self.pbx_user_uuid,
            'auth_id': self.auth_id,
            'pbx_user_uuid': self.pbx_user_uuid,
        }
        self.user_agent = 'user-agent'
        self.remote_addr = '192.168.1.1'

        self.token = token.Token(
            self.id_,
            auth_id=self.auth_id,
            pbx_user_uuid=self.pbx_user_uuid,
            xivo_uuid=self.xivo_uuid,
            issued_t=self.issued_at,
            expire_t=self.expires_at,
            acl=self.acl,
            metadata=self.metadata,
            session_uuid=self.session_uuid,
            user_agent=self.user_agent,
            remote_addr=self.remote_addr,
        )
        self.utc_issued_at = '2016-11-24T18:17:51.535370'
        self.utc_expires_at = '2016-11-24T18:18:33.535370'

    def test_is_expired_when_time_is_in_the_future(self):
        self.token.expire_t = time.time() + 60

        self.assertFalse(self.token.is_expired())

    def test_is_expired_when_time_is_in_the_past(self):
        self.token.expire_t = time.time() - 60

        self.assertTrue(self.token.is_expired())

    def test_is_expired_when_no_expiration(self):
        self.token.expire_t = None

        self.assertFalse(self.token.is_expired())


def make_remover(token_cleanup_interval=60):
    config = {
        'token_cleanup_interval': token_cleanup_interval,
        'token_cleanup_batch_size': 5000,
        'debug': False,
    }
    return ExpiredTokenRemover(config, Mock(), Mock(), Mock(), Mock())


@pytest.fixture
def remover():
    remover = make_remover()
    remover._leader_lock = Mock()
    remover._purge_expired_sessions = Mock()
    remover._purge_expired_saml_sessions = Mock()
    remover._notify_expire_soon = Mock()
    return remover


def test_run_once_runs_cleanups_in_order(remover):
    parent = Mock()
    parent.attach_mock(remover._purge_expired_sessions, 'purge_sessions')
    parent.attach_mock(remover._purge_expired_saml_sessions, 'purge_saml')
    parent.attach_mock(remover._notify_expire_soon, 'notify')

    remover._run_once()

    assert parent.mock_calls == [
        call.purge_sessions(),
        call.purge_saml(),
        call.notify(),
    ]


def test_loop_skips_cleanups_when_not_leader(remover, caplog):
    def not_leader_and_stop():
        remover._tombstone.set()
        return False

    remover._leader_lock.hold.side_effect = not_leader_and_stop

    with caplog.at_level(logging.DEBUG):
        remover._loop()

    remover._purge_expired_sessions.assert_not_called()
    remover._purge_expired_saml_sessions.assert_not_called()
    remover._notify_expire_soon.assert_not_called()
    assert 'ExpiredTokenRemover took' not in caplog.text


def test_loop_survives_lock_errors(remover):
    def fail_and_stop():
        remover._tombstone.set()
        raise Exception('database is unreachable')

    remover._leader_lock.hold.side_effect = fail_and_stop

    remover._loop()

    remover._purge_expired_sessions.assert_not_called()


@patch('wazo_auth.token.Session')
def test_run_once_survives_cleanup_errors(session, remover):
    remover._purge_expired_sessions.side_effect = Exception('boom')

    remover._run_once()

    session.close.assert_called_once()


def test_loop_releases_lock_on_exit(remover):
    remover._tombstone.set()

    remover._loop()

    remover._leader_lock.release.assert_called_once()
    remover._leader_lock.hold.assert_not_called()


def test_loop_ticks_then_releases(remover):
    def become_leader_and_stop():
        remover._tombstone.set()
        return True

    remover._leader_lock.hold.side_effect = become_leader_and_stop

    remover._loop()

    remover._purge_expired_sessions.assert_called_once()
    remover._leader_lock.release.assert_called_once()


@pytest.mark.parametrize('interval', [0, 0.5])
def test_disabled_when_interval_below_one(interval):
    remover = make_remover(token_cleanup_interval=interval)

    remover.start()
    remover.stop()


def test_stop_before_start_does_not_raise_and_sets_the_tombstone(remover):
    remover.stop()

    assert remover._tombstone.is_set()


def test_start_after_stop_exits_immediately(remover):
    remover.stop()
    remover.start()

    remover._thread.join(timeout=5)
    assert not remover._thread.is_alive()
    remover._purge_expired_sessions.assert_not_called()


@patch('wazo_auth.token.Session')
def test_leadership_released_after_consecutive_failures(session, remover):
    remover._purge_expired_sessions.side_effect = Exception('boom')

    for _ in range(ExpiredTokenRemover.MAX_CONSECUTIVE_FAILURES):
        remover._run_once()

    remover._leader_lock.release.assert_called_once()


@patch('wazo_auth.token.Session')
def test_a_successful_tick_resets_the_failure_count(session, remover):
    failures = ExpiredTokenRemover.MAX_CONSECUTIVE_FAILURES - 1

    remover._purge_expired_sessions.side_effect = Exception('boom')
    for _ in range(failures):
        remover._run_once()
    remover._purge_expired_sessions.side_effect = None
    remover._run_once()
    remover._purge_expired_sessions.side_effect = Exception('boom')
    for _ in range(failures):
        remover._run_once()

    remover._leader_lock.release.assert_not_called()
