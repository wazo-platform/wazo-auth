# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from types import SimpleNamespace
from unittest.mock import ANY, Mock, call, patch
from uuid import uuid4

import pytest

from ..config import _DEFAULT_CONFIG
from ..controller import Controller
from ..database.helpers import StartupLockInterrupted


@pytest.fixture
def make_controller():
    def _make(**config_overrides):
        config = dict(_DEFAULT_CONFIG, uuid=str(uuid4()), **config_overrides)
        return Controller(config)

    with (
        patch('wazo_auth.database.helpers.Session'),
        patch('wazo_auth.controller.Session'),
        patch('wazo_auth.controller.CoreRestApi'),
        patch('wazo_auth.token.ExpiredTokenRemover'),
        patch('wazo_auth.controller.ServiceDiscoveryComponent'),
    ):
        yield _make


@pytest.fixture
def run_environment():
    with (
        patch('wazo_auth.controller.db_ready'),
        patch('wazo_auth.controller.http') as http,
        patch('wazo_auth.controller.startup') as startup,
        patch('wazo_auth.controller.startup_lock') as startup_lock,
        patch('wazo_auth.controller.Session'),
        patch('wazo_auth.controller.signal'),
    ):
        yield SimpleNamespace(http=http, startup=startup, startup_lock=startup_lock)


def test_create_controller(make_controller):
    controller = make_controller()

    assert controller._config
    assert controller._roles == {'api', 'scheduler', 'init'}


def test_pool_reserves_a_connection_for_the_scheduler_leader(make_controller):
    min_threads = _DEFAULT_CONFIG['rest_api']['min_threads']
    max_threads = _DEFAULT_CONFIG['rest_api']['max_threads']
    overflow = max_threads - min_threads

    with patch('wazo_auth.controller.init_db') as init_db:
        make_controller()
        init_db.assert_called_once_with(
            ANY, pool_size=min_threads + 2, max_overflow=overflow
        )

    with patch('wazo_auth.controller.init_db') as init_db:
        make_controller(roles=['api'])
        init_db.assert_called_once_with(
            ANY, pool_size=min_threads, max_overflow=overflow
        )


def test_run_default_roles_order(make_controller, run_environment):
    controller = make_controller()
    parent = Mock()
    parent.attach_mock(controller._service_discovery.start, 'sd_start')
    parent.attach_mock(controller._service_discovery.stop, 'sd_stop')
    parent.attach_mock(controller._expired_token_remover.start, 'remover_start')
    parent.attach_mock(controller._rest_api.run, 'rest_api_run')

    controller.run()

    assert parent.mock_calls == [
        call.sd_start(),
        call.remover_start(),
        call.rest_api_run(),
        call.sd_stop(),
    ]
    run_environment.startup.update_policy_on_startup.assert_called_once()
    run_environment.http.init_top_tenant.assert_called_once_with(controller.dao)
    run_environment.startup.create_initial_user.assert_not_called()
    run_environment.startup.check_unavailable_authentication_methods.assert_called_once()
    run_environment.startup_lock.assert_called_once()


def test_run_default_roles_gating_flags(make_controller, run_environment):
    controller = make_controller(
        update_policy_on_startup=False,
        bootstrap_user_on_startup=True,
    )

    controller.run()

    run_environment.startup.update_policy_on_startup.assert_not_called()
    run_environment.startup.create_initial_user.assert_called_once_with(
        controller._config
    )


def test_run_api_only(make_controller, run_environment):
    controller = make_controller(roles=['api'])

    controller.run()

    controller._service_discovery.start.assert_called_once()
    controller._rest_api.run.assert_called_once()
    controller._service_discovery.stop.assert_called_once()
    controller._expired_token_remover.start.assert_not_called()
    run_environment.http.init_top_tenant.assert_called_once_with(controller.dao)
    run_environment.startup.update_policy_on_startup.assert_not_called()
    run_environment.startup.check_unavailable_authentication_methods.assert_not_called()
    run_environment.startup_lock.assert_not_called()


def test_run_without_init_role_warns_about_skipped_startup_tasks(
    make_controller, run_environment, caplog
):
    controller = make_controller(
        roles=['api'],
        update_policy_on_startup=True,
        bootstrap_user_on_startup=True,
    )

    with caplog.at_level(logging.WARNING):
        controller.run()

    assert 'update_policy_on_startup is enabled' in caplog.text
    assert 'bootstrap_user_on_startup is enabled' in caplog.text


def test_run_scheduler_only(make_controller, run_environment):
    controller = make_controller(roles=['scheduler'])
    # unblock the _stopped.wait() as soon as the components are up
    controller._expired_token_remover.start.side_effect = controller._stopped.set

    controller.run()

    controller._expired_token_remover.start.assert_called_once()
    controller._service_discovery.start.assert_not_called()
    controller._rest_api.run.assert_not_called()
    run_environment.http.init_top_tenant.assert_called_once_with(controller.dao)
    run_environment.startup_lock.assert_not_called()


def test_run_retries_until_the_top_tenant_exists(make_controller, run_environment):
    controller = make_controller(roles=['api'])
    run_environment.http.init_top_tenant.side_effect = [
        Exception('relation "auth_tenant" does not exist'),
        Exception('no top tenant yet'),
        None,
    ]

    with patch('wazo_auth.controller.time') as time_mock:
        time_mock.monotonic.side_effect = [0, 1, 2]
        controller.run()

    assert run_environment.http.init_top_tenant.call_count == 3
    controller._rest_api.run.assert_called_once()


def test_run_gives_up_waiting_for_the_top_tenant(make_controller, run_environment):
    controller = make_controller(roles=['api'])
    run_environment.http.init_top_tenant.side_effect = Exception('still no schema')

    with patch('wazo_auth.controller.time') as time_mock:
        time_mock.monotonic.side_effect = [0, 400]
        with pytest.raises(Exception):
            controller.run()

    controller._rest_api.run.assert_not_called()


def test_run_aborts_when_stopped_during_the_top_tenant_wait(
    make_controller, run_environment
):
    controller = make_controller()

    def fail_and_request_shutdown(dao):
        controller._stopped.set()
        raise Exception('relation "auth_tenant" does not exist')

    run_environment.http.init_top_tenant.side_effect = fail_and_request_shutdown

    with patch('wazo_auth.controller.time') as time_mock:
        time_mock.monotonic.side_effect = [0, 1]
        controller.run()

    run_environment.startup.update_policy_on_startup.assert_not_called()
    controller._service_discovery.start.assert_not_called()
    controller._expired_token_remover.start.assert_not_called()
    controller._rest_api.run.assert_not_called()


def test_run_aborts_when_stopped_during_the_one_shots(make_controller, run_environment):
    controller = make_controller()
    run_environment.startup.check_unavailable_authentication_methods.side_effect = (
        lambda *args: controller._stopped.set()
    )

    controller.run()

    controller._service_discovery.start.assert_not_called()
    controller._expired_token_remover.start.assert_not_called()
    controller._rest_api.run.assert_not_called()


def test_run_stops_cleanly_when_interrupted_waiting_for_the_lock(
    make_controller, run_environment
):
    controller = make_controller(roles=['init', 'api'])
    run_environment.startup_lock.side_effect = StartupLockInterrupted()

    controller.run()

    run_environment.startup.update_policy_on_startup.assert_not_called()
    controller._service_discovery.start.assert_not_called()
    controller._rest_api.run.assert_not_called()


def test_run_init_only(make_controller, run_environment):
    controller = make_controller(roles=['init'])

    controller.run()

    run_environment.startup.update_policy_on_startup.assert_called_once()
    run_environment.http.init_top_tenant.assert_called_once_with(controller.dao)
    run_environment.startup.check_unavailable_authentication_methods.assert_called_once()
    run_environment.startup_lock.assert_called_once()
    controller._service_discovery.start.assert_not_called()
    controller._expired_token_remover.start.assert_not_called()
    controller._rest_api.run.assert_not_called()


def test_run_init_one_shots_run_inside_the_lock(make_controller, run_environment):
    controller = make_controller(roles=['init'], bootstrap_user_on_startup=True)
    parent = Mock()
    parent.attach_mock(run_environment.startup_lock, 'lock')
    parent.attach_mock(run_environment.startup.update_policy_on_startup, 'policies')
    parent.attach_mock(run_environment.startup.create_initial_user, 'bootstrap')
    parent.attach_mock(
        run_environment.startup.check_unavailable_authentication_methods,
        'check_methods',
    )

    controller.run()

    assert parent.mock_calls == [
        call.lock(ANY, stop_event=controller._stopped),
        call.lock(ANY, stop_event=controller._stopped).__enter__(),
        call.policies(ANY, ANY, ANY, ANY),
        call.bootstrap(controller._config),
        call.check_methods(controller.dao, ANY),
        call.lock(ANY, stop_event=controller._stopped).__exit__(None, None, None),
    ]


def test_stop_default_roles(make_controller):
    controller = make_controller()

    controller.stop('TEST')

    controller._stopping_thread.join()
    controller._expired_token_remover.stop.assert_called_once()
    controller._rest_api.stop.assert_called_once()
    assert controller._stopped.is_set()


def test_stop_api_only(make_controller):
    controller = make_controller(roles=['api'])

    controller.stop('TEST')

    controller._stopping_thread.join()
    controller._expired_token_remover.stop.assert_not_called()
    controller._rest_api.stop.assert_called_once()


def test_stop_scheduler_only(make_controller):
    controller = make_controller(roles=['scheduler'])

    controller.stop('TEST')

    assert controller._stopping_thread is None
    controller._expired_token_remover.stop.assert_called_once()
    controller._rest_api.stop.assert_not_called()
    assert controller._stopped.is_set()
