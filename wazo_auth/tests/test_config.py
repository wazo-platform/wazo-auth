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
    assert _DEFAULT_CONFIG['roles'] == {'api': True, 'scheduler': True, 'init': True}
    assert set(_DEFAULT_CONFIG['roles']) == set(VALID_ROLES)


def test_cli_no_role_leaves_roles_unset():
    result = _parse_cli_args([])
    assert 'roles' not in result


def test_cli_role_is_repeatable_and_disables_the_others():
    result = _parse_cli_args(['--role', 'api', '--role', 'scheduler'])
    assert result['roles'] == {'api': True, 'scheduler': True, 'init': False}


def test_cli_unknown_role_is_rejected():
    with pytest.raises(SystemExit):
        _parse_cli_args(['--role', 'bogus'])


def test_cli_listen_port_sets_the_rest_api_port():
    result = _parse_cli_args(['--listen-port', '9498'])

    assert result['rest_api'] == {'port': 9498}


def test_cli_no_listen_port_leaves_rest_api_unset():
    result = _parse_cli_args([])

    assert 'rest_api' not in result


@patch('wazo_auth.config.read_config_file_hierarchy_accumulating_list')
def test_cli_listen_port_overrides_file_port_but_keeps_listen(read_config_files):
    read_config_files.return_value = {'rest_api': {'port': 9497, 'listen': '0.0.0.0'}}

    config = get_config(['--listen-port', '9498'])

    assert config['rest_api']['port'] == 9498
    assert config['rest_api']['listen'] == '0.0.0.0'


@patch('wazo_auth.config.read_config_file_hierarchy_accumulating_list')
def test_advertise_port_defaults_to_the_rest_api_port(read_config_files):
    read_config_files.return_value = {}

    config = get_config([])

    assert config['service_discovery']['advertise_port'] == 9497
    # the derivation must not clobber the other service_discovery keys
    assert config['service_discovery']['advertise_address'] == 'auto'
    assert config['service_discovery']['ttl_interval'] == 30


@patch('wazo_auth.config.read_config_file_hierarchy_accumulating_list')
def test_advertise_port_follows_a_file_configured_port(read_config_files):
    read_config_files.return_value = {'rest_api': {'port': 9600}}

    config = get_config([])

    assert config['service_discovery']['advertise_port'] == 9600


@patch('wazo_auth.config.read_config_file_hierarchy_accumulating_list')
def test_advertise_port_follows_the_cli_port(read_config_files):
    read_config_files.return_value = {}

    config = get_config(['--listen-port', '9498'])

    assert config['service_discovery']['advertise_port'] == 9498


@patch('wazo_auth.config.read_config_file_hierarchy_accumulating_list')
def test_explicit_advertise_port_is_respected(read_config_files):
    read_config_files.return_value = {
        'rest_api': {'port': 9600},
        'service_discovery': {'advertise_port': 12345},
    }

    config = get_config([])

    assert config['service_discovery']['advertise_port'] == 12345


def test_normalize_roles_keeps_enabled_roles_sorted():
    roles = {'scheduler': True, 'api': True, 'init': False}
    assert _normalize_roles(roles) == ['api', 'scheduler']


def test_normalize_roles_rejects_unknown_role():
    with pytest.raises(ValueError):
        _normalize_roles({'api': True, 'bogus': True})


def test_normalize_roles_rejects_all_roles_disabled():
    with pytest.raises(ValueError):
        _normalize_roles({'api': False, 'scheduler': False, 'init': False})


def test_normalize_roles_rejects_a_list():
    with pytest.raises(ValueError, match='must be a map'):
        _normalize_roles(['api'])


def test_normalize_roles_rejects_a_scalar_string():
    with pytest.raises(ValueError, match='must be a map'):
        _normalize_roles('api')


def test_normalize_roles_rejects_none():
    with pytest.raises(ValueError, match='must be a map'):
        _normalize_roles(None)


@patch('wazo_auth.config.read_config_file_hierarchy_accumulating_list')
def test_cli_roles_override_file_roles(read_config_files):
    read_config_files.return_value = {'roles': {'api': True}}
    config = get_config(['--role', 'scheduler'])
    assert config['roles'] == ['scheduler']


@patch('wazo_auth.config.read_config_file_hierarchy_accumulating_list')
def test_file_roles_merge_per_key_with_default_roles(read_config_files):
    read_config_files.return_value = {'roles': {'scheduler': False, 'init': False}}
    config = get_config([])
    assert config['roles'] == ['api']
