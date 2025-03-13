from unittest.mock import patch
from uuid import uuid4

import pytest

from ..config import _DEFAULT_CONFIG
from ..controller import Controller


@patch('wazo_auth.database.helpers.Session')
def test_create_controller(mock_session):
    config = dict(_DEFAULT_CONFIG, uuid=uuid4())
    controller = Controller(config)
    assert controller._config


@pytest.fixture
@patch('wazo_auth.database.helpers.Session')
def controller(mock_session):
    config = dict(_DEFAULT_CONFIG, uuid=uuid4())
    return Controller(config)


@patch('wazo_auth.database.helpers.Session')
@patch('wazo_auth.http_server.CoreRestApi')
@patch('wazo_auth.token.ExpiredTokenRemover')
def test_controller_run(mock_session, mock_rest_api, controller: Controller):
    controller.run()
