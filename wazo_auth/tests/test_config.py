# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest.mock import patch

import pytest

from ..config import (
    _DEFAULT_CONFIG,
    VALID_ROLES,
    _normalize_roles,
    _parse_cli_args,
    get_config,
)


def test_default_config_roles():
    assert _DEFAULT_CONFIG['roles'] == ['api', 'scheduler', 'init']
    assert _DEFAULT_CONFIG['roles'] == list(VALID_ROLES)


def test_cli_no_role_leaves_roles_unset():
    result = _parse_cli_args([])
    assert 'roles' not in result


def test_cli_role_is_repeatable():
    result = _parse_cli_args(['--role', 'api', '--role', 'scheduler'])
    assert result['roles'] == ['api', 'scheduler']


def test_cli_unknown_role_is_rejected():
    with pytest.raises(SystemExit):
        _parse_cli_args(['--role', 'bogus'])


def test_normalize_roles_dedupes_and_sorts():
    assert _normalize_roles(['scheduler', 'api', 'scheduler']) == ['api', 'scheduler']


def test_normalize_roles_rejects_unknown_role():
    with pytest.raises(ValueError):
        _normalize_roles(['api', 'bogus'])


def test_normalize_roles_rejects_empty_list():
    with pytest.raises(ValueError):
        _normalize_roles([])


def test_normalize_roles_rejects_a_scalar_string():
    with pytest.raises(ValueError, match='must be a list'):
        _normalize_roles('api')


def test_normalize_roles_rejects_none():
    with pytest.raises(ValueError, match='must be a list'):
        _normalize_roles(None)


@patch('wazo_auth.config.read_config_file_hierarchy_accumulating_list')
def test_cli_roles_override_file_roles(read_config_files):
    read_config_files.return_value = {'roles': ['api']}
    config = get_config(['--role', 'scheduler'])
    assert config['roles'] == ['scheduler']


@patch('wazo_auth.config.read_config_file_hierarchy_accumulating_list')
def test_file_roles_override_default_roles(read_config_files):
    read_config_files.return_value = {'roles': ['api']}
    config = get_config([])
    assert config['roles'] == ['api']
