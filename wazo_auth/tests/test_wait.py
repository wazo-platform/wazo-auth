# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from ..wait import TIMEOUT, _parse_cli_args


def test_no_args_leaves_port_unset():
    args = _parse_cli_args([])

    assert args.port is None


def test_port_argument_is_an_int():
    args = _parse_cli_args(['--port', '9498'])

    assert args.port == 9498


def test_no_args_uses_default_timeout():
    args = _parse_cli_args([])

    assert args.timeout == TIMEOUT


def test_timeout_argument_is_an_int():
    args = _parse_cli_args(['--timeout', '600'])

    assert args.timeout == 600
