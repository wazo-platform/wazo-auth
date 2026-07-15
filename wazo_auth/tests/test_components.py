# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest.mock import patch, sentinel

import pytest

from ..components import ServiceDiscoveryComponent


@patch('wazo_auth.components.ServiceCatalogRegistration')
def test_start_registers(registration_factory):
    component = ServiceDiscoveryComponent(sentinel.arg1, sentinel.arg2)

    component.start()

    registration_factory.assert_called_once_with(sentinel.arg1, sentinel.arg2)
    registration_factory.return_value.__enter__.assert_called_once()


@patch('wazo_auth.components.ServiceCatalogRegistration')
def test_stop_deregisters(registration_factory):
    component = ServiceDiscoveryComponent()
    component.start()

    component.stop()

    registration_factory.return_value.__exit__.assert_called_once_with(None, None, None)


@patch('wazo_auth.components.ServiceCatalogRegistration')
def test_stop_without_start_is_a_noop(registration_factory):
    component = ServiceDiscoveryComponent()

    component.stop()

    registration_factory.assert_not_called()


@patch('wazo_auth.components.ServiceCatalogRegistration')
def test_double_stop_deregisters_once(registration_factory):
    component = ServiceDiscoveryComponent()
    component.start()

    component.stop()
    component.stop()

    registration_factory.return_value.__exit__.assert_called_once()


@patch('wazo_auth.components.ServiceCatalogRegistration')
def test_failed_start_propagates_and_stop_stays_a_noop(registration_factory):
    registration_factory.return_value.__enter__.side_effect = RuntimeError('boom')
    component = ServiceDiscoveryComponent()

    with pytest.raises(RuntimeError):
        component.start()

    component.stop()
    registration_factory.return_value.__exit__.assert_not_called()
