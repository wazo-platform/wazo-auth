# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest.mock import ANY, Mock, call, patch

import pytest

from ..database import upgrade


@pytest.fixture
def environment():
    with (
        patch('wazo_auth.database.database.alembic') as alembic,
        patch('wazo_auth.database.database.startup_lock') as startup_lock,
        patch('wazo_auth.database.database.wait_is_ready') as wait_is_ready,
        patch('wazo_auth.database.database.create_engine') as create_engine,
    ):
        parent = Mock()
        parent.attach_mock(wait_is_ready, 'wait_is_ready')
        parent.attach_mock(startup_lock, 'startup_lock')
        parent.attach_mock(alembic.command.upgrade, 'alembic_upgrade')
        parent.create_engine = create_engine
        yield parent


def test_upgrade_runs_alembic_under_the_lock(environment):
    upgrade('postgresql://example')

    engine = environment.create_engine.return_value
    assert environment.mock_calls == [
        call.wait_is_ready(engine),
        call.startup_lock(engine),
        call.startup_lock().__enter__(),
        call.alembic_upgrade(ANY, 'head'),
        call.startup_lock().__exit__(None, None, None),
    ]
    engine.dispose.assert_called_once()


def test_upgrade_disposes_engine_on_failure(environment):
    environment.alembic_upgrade.side_effect = RuntimeError('migration failed')

    with pytest.raises(RuntimeError):
        upgrade('postgresql://example')

    environment.create_engine.return_value.dispose.assert_called_once()
