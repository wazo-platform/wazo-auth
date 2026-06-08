from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from ..config import _DEFAULT_CONFIG
from ..controller import MISCONFIGURATION_EXIT_CODE, Controller


@patch('wazo_auth.database.helpers.Session')
def test_create_controller(mock_session):
    config = dict(_DEFAULT_CONFIG, uuid=uuid4())
    controller = Controller(config)
    assert controller._config


@patch('wazo_auth.controller.ServiceCatalogRegistration')
@patch('wazo_auth.controller.http')
@patch('wazo_auth.controller.db_ready')
@patch('wazo_auth.database.helpers.Session')
def test_run_as_primary_starts_the_expired_token_remover(
    mock_session, mock_db_ready, mock_http, mock_service_discovery
):
    config = dict(_DEFAULT_CONFIG, uuid=uuid4(), update_policy_on_startup=False)
    controller = Controller(config)
    controller._rest_api = Mock()
    controller._expired_token_remover = Mock()

    with patch.object(controller, '_check_unavailable_authentication_methods'):
        controller.run()

    controller._expired_token_remover.start.assert_called_once_with()
    controller._rest_api.run.assert_called_once_with()


@patch('wazo_auth.controller.http')
@patch('wazo_auth.controller.db_ready')
@patch('wazo_auth.database.helpers.Session')
def test_run_as_worker_serves_http_without_background_work(
    mock_session, mock_db_ready, mock_http
):
    config = dict(_DEFAULT_CONFIG, uuid=uuid4(), http_worker=True)
    config['rest_api'] = dict(config['rest_api'], reuse_port=True)
    controller = Controller(config)
    controller._rest_api = Mock()
    controller._expired_token_remover = Mock()

    controller.run()

    controller._rest_api.run.assert_called_once_with()
    controller._expired_token_remover.start.assert_not_called()


@patch('wazo_auth.database.helpers.Session')
def test_worker_exits_when_reuse_port_disabled(mock_session):
    config = dict(_DEFAULT_CONFIG, uuid=uuid4(), http_worker=True)
    config['rest_api'] = dict(config['rest_api'], reuse_port=False)
    controller = Controller(config)

    with pytest.raises(SystemExit) as excinfo:
        controller.run()

    assert excinfo.value.code == MISCONFIGURATION_EXIT_CODE
