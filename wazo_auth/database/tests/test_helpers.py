# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from unittest.mock import Mock, patch

import pytest

from ..helpers import (
    _STARTUP_LOCK_HOLDER_QUERY,
    ADVISORY_LOCK_CLASSID,
    SCHEDULER_LOCK_OBJID,
    STARTUP_LOCK_OBJID,
    SchedulerLeaderLock,
    StartupLockInterrupted,
    StartupLockTimeout,
    startup_lock,
)

LOCK_PARAMS = {'classid': ADVISORY_LOCK_CLASSID, 'objid': STARTUP_LOCK_OBJID}
SCHEDULER_LOCK_PARAMS = {
    'classid': ADVISORY_LOCK_CLASSID,
    'objid': SCHEDULER_LOCK_OBJID,
}


@pytest.fixture
def engine():
    return Mock()


@pytest.fixture
def connection(engine):
    connection = engine.connect.return_value.execution_options.return_value
    connection.execute.return_value.scalar.return_value = True
    return connection


def executed_statements(connection):
    return [str(call.args[0]) for call in connection.execute.call_args_list]


def executed_params(connection):
    return [call.args[1] for call in connection.execute.call_args_list]


def holder_row(pid=42):
    return Mock(first=Mock(return_value=Mock(pid=pid)))


def test_lock_uncontended(engine, connection):
    with startup_lock(engine, timeout=300):
        pass

    engine.connect.return_value.execution_options.assert_called_once_with(
        isolation_level='AUTOCOMMIT'
    )
    assert executed_statements(connection) == [
        'SELECT pg_try_advisory_lock(:classid, :objid)',
        'SELECT pg_advisory_unlock(:classid, :objid)',
    ]
    assert all(params == LOCK_PARAMS for params in executed_params(connection))
    connection.close.assert_called_once()


@patch('wazo_auth.database.helpers.time')
def test_lock_contended_polls_and_logs_the_holder(
    time_mock, engine, connection, caplog
):
    time_mock.monotonic.return_value = 0.0
    connection.execute.side_effect = [
        Mock(scalar=Mock(return_value=False)),
        holder_row(pid=42),
        Mock(scalar=Mock(return_value=True)),
        Mock(),
    ]

    with caplog.at_level(logging.INFO):
        with startup_lock(engine, timeout=300):
            pass

    assert executed_statements(connection) == [
        'SELECT pg_try_advisory_lock(:classid, :objid)',
        _STARTUP_LOCK_HOLDER_QUERY,
        'SELECT pg_try_advisory_lock(:classid, :objid)',
        'SELECT pg_advisory_unlock(:classid, :objid)',
    ]
    assert 'waiting for the wazo-auth startup lock' in caplog.text
    assert 'held by pid 42' in caplog.text
    time_mock.sleep.assert_called_once_with(2)


@patch('wazo_auth.database.helpers.time')
def test_lock_wait_times_out(time_mock, engine, connection):
    time_mock.monotonic.side_effect = [0.0, 400.0]
    connection.execute.side_effect = [
        Mock(scalar=Mock(return_value=False)),
        holder_row(pid=42),
    ]

    with pytest.raises(StartupLockTimeout, match='within 300s.*held by pid 42'):
        with startup_lock(engine, timeout=300):
            raise AssertionError('the body must not run')

    # the lock was never acquired: no unlock, but the connection is closed
    time_mock.sleep.assert_not_called()
    connection.close.assert_called_once()


def test_lock_wait_interrupted_by_stop_event(engine, connection):
    connection.execute.return_value.scalar.return_value = False
    stop_event = Mock()
    stop_event.wait.return_value = True

    with pytest.raises(StartupLockInterrupted):
        with startup_lock(engine, timeout=300, stop_event=stop_event):
            raise AssertionError('the body must not run')

    # the lock was never acquired: no unlock, but the connection is closed
    assert executed_statements(connection) == [
        'SELECT pg_try_advisory_lock(:classid, :objid)',
        _STARTUP_LOCK_HOLDER_QUERY,
    ]
    connection.close.assert_called_once()


def test_lock_released_when_body_raises(engine, connection):
    with pytest.raises(RuntimeError):
        with startup_lock(engine, timeout=300):
            raise RuntimeError('boom')

    assert executed_statements(connection)[-1] == (
        'SELECT pg_advisory_unlock(:classid, :objid)'
    )
    connection.close.assert_called_once()


def test_unlock_failure_invalidates_connection(engine, connection):
    connection.execute.side_effect = [
        Mock(scalar=Mock(return_value=True)),
        Exception('connection is dead'),
    ]

    with startup_lock(engine, timeout=300):
        pass

    connection.invalidate.assert_called_once()
    connection.close.assert_called_once()


@pytest.fixture
def leader_lock(engine):
    return SchedulerLeaderLock(engine)


def test_scheduler_hold_acquires_on_first_call(engine, connection, leader_lock, caplog):
    with caplog.at_level(logging.INFO):
        assert leader_lock.hold() is True

    engine.connect.return_value.execution_options.assert_called_once_with(
        isolation_level='AUTOCOMMIT'
    )
    assert executed_statements(connection) == [
        'SELECT pg_try_advisory_lock(:classid, :objid)',
    ]
    assert executed_params(connection) == [SCHEDULER_LOCK_PARAMS]
    connection.close.assert_not_called()
    assert 'acquired the wazo-auth scheduler leader lock' in caplog.text


def test_scheduler_hold_contended_returns_false_and_closes(
    engine, connection, leader_lock
):
    connection.execute.return_value.scalar.return_value = False

    assert leader_lock.hold() is False
    assert leader_lock.hold() is False

    connection.close.assert_called()
    assert engine.connect.call_count == 2  # reconnects on every attempt


def test_scheduler_hold_when_leader_pings_only(engine, connection, leader_lock):
    assert leader_lock.hold() is True
    assert leader_lock.hold() is True

    assert executed_statements(connection) == [
        'SELECT pg_try_advisory_lock(:classid, :objid)',
        'SELECT 1',
    ]
    assert engine.connect.call_count == 1


def test_scheduler_hold_dead_connection_reacquires(
    engine, connection, leader_lock, caplog
):
    connection.execute.side_effect = [
        Mock(scalar=Mock(return_value=True)),
        Exception('connection is dead'),
        Mock(scalar=Mock(return_value=True)),
    ]

    assert leader_lock.hold() is True
    with caplog.at_level(logging.WARNING):
        assert leader_lock.hold() is True

    connection.invalidate.assert_called_once()
    assert engine.connect.call_count == 2
    assert 'lost the wazo-auth scheduler leader lock' in caplog.text


def test_scheduler_hold_acquire_error_closes_and_raises(
    engine, connection, leader_lock
):
    connection.execute.side_effect = Exception('database is unreachable')

    with pytest.raises(Exception):
        leader_lock.hold()

    connection.invalidate.assert_called_once()
    connection.close.assert_called_once()


def test_scheduler_release_unlocks_and_closes(engine, connection, leader_lock):
    leader_lock.hold()

    leader_lock.release()

    assert executed_statements(connection)[-1] == (
        'SELECT pg_advisory_unlock(:classid, :objid)'
    )
    connection.close.assert_called_once()


def test_scheduler_release_is_idempotent(engine, connection, leader_lock):
    leader_lock.hold()

    leader_lock.release()
    leader_lock.release()

    connection.close.assert_called_once()


def test_scheduler_release_when_never_held_is_a_noop(engine, leader_lock):
    leader_lock.release()

    engine.connect.assert_not_called()


def test_scheduler_release_failure_invalidates(engine, connection, leader_lock):
    connection.execute.side_effect = [
        Mock(scalar=Mock(return_value=True)),
        Exception('connection is dead'),
    ]
    leader_lock.hold()

    leader_lock.release()

    connection.invalidate.assert_called_once()
    connection.close.assert_called_once()
