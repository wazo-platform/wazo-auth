# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from unittest.mock import patch
from uuid import uuid4

import pytest

from ..config import _DEFAULT_CONFIG
from ..main import main


@pytest.fixture
def environment():
    with (
        patch('wazo_auth.main.xivo_logging'),
        patch('wazo_auth.main.change_user'),
        patch('wazo_auth.main.set_xivo_uuid'),
        patch('wazo_auth.main.database') as database,
        patch('wazo_auth.main.Controller'),
        patch('wazo_auth.main.get_config') as get_config,
    ):
        yield get_config, database


def make_config(**overrides):
    return dict(_DEFAULT_CONFIG, uuid=str(uuid4()), **overrides)


def test_invalid_configuration_exits_with_ex_config(environment, capsys):
    get_config, _ = environment
    get_config.side_effect = ValueError('invalid roles')

    with pytest.raises(SystemExit) as raised:
        main()

    assert raised.value.code == 78
    assert 'invalid configuration: invalid roles' in capsys.readouterr().err


def test_db_upgrade_runs_with_the_init_role(environment):
    get_config, database = environment
    get_config.return_value = make_config(db_upgrade_on_startup=True)

    main()

    database.upgrade.assert_called_once()


def test_db_upgrade_skipped_without_the_init_role_warns(environment, caplog):
    get_config, database = environment
    get_config.return_value = make_config(
        db_upgrade_on_startup=True, roles=['api', 'scheduler']
    )

    with caplog.at_level(logging.WARNING):
        main()

    database.upgrade.assert_not_called()
    assert 'db_upgrade_on_startup is enabled' in caplog.text
