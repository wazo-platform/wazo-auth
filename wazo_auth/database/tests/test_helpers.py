# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from unittest.mock import Mock, patch

import pytest

from ..helpers import (
    ADVISORY_LOCK_CLASSID,
    STARTUP_LOCK_OBJID,
    StartupLockInterrupted,
    startup_lock,
)

LOCK_PARAMS = {'classid': ADVISORY_LOCK_CLASSID, 'objid': STARTUP_LOCK_OBJID}


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


def test_lock_uncontended(engine, connection):
    with startup_lock(engine):
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
def test_lock_contended_polls_and_logs(time_mock, engine, connection, caplog):
    connection.execute.side_effect = [
        Mock(scalar=Mock(return_value=False)),
        Mock(scalar=Mock(return_value=True)),
        Mock(),
    ]

    with caplog.at_level(logging.INFO):
        with startup_lock(engine):
            pass

    assert executed_statements(connection) == [
        'SELECT pg_try_advisory_lock(:classid, :objid)',
        'SELECT pg_try_advisory_lock(:classid, :objid)',
        'SELECT pg_advisory_unlock(:classid, :objid)',
    ]
    assert 'waiting for the wazo-auth startup lock' in caplog.text
    time_mock.sleep.assert_called_once_with(2)


def test_lock_wait_interrupted_by_stop_event(engine, connection):
    connection.execute.return_value.scalar.return_value = False
    stop_event = Mock()
    stop_event.wait.return_value = True

    with pytest.raises(StartupLockInterrupted):
        with startup_lock(engine, stop_event=stop_event):
            raise AssertionError('the body must not run')

    # the lock was never acquired: no unlock, but the connection is closed
    assert executed_statements(connection) == [
        'SELECT pg_try_advisory_lock(:classid, :objid)',
    ]
    connection.close.assert_called_once()


def test_lock_released_when_body_raises(engine, connection):
    with pytest.raises(RuntimeError):
        with startup_lock(engine):
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

    with startup_lock(engine):
        pass

    connection.invalidate.assert_called_once()
    connection.close.assert_called_once()
