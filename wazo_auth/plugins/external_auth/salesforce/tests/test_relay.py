# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json
from unittest import TestCase
from unittest.mock import Mock, patch

from hamcrest import assert_that, contains_string, equal_to, is_, not_

from ..relay import RelayListener
from .helpers import CODE


@patch('wazo_auth.plugins.external_auth.salesforce.relay.websocket')
class TestRelayListener(TestCase):
    def test_listens_on_the_state_and_hands_over_the_code(self, websocket):
        on_code = Mock()
        relay = RelayListener('wss://oauth.example.com', 'the-state', on_code)

        relay.run()

        args, kwargs = websocket.WebSocketApp.call_args
        assert_that(args[0], equal_to('wss://oauth.example.com/ws/the-state'))
        ws = websocket.WebSocketApp.return_value
        ws.run_forever.assert_called_once_with()
        kwargs['on_message'](ws, json.dumps({'code': CODE, 'state': 'the-state'}))
        on_code.assert_called_once_with(CODE)
        assert_that(ws.close.call_count, equal_to(2))
        assert_that(relay.daemon, is_(True))

    def test_closes_the_socket_when_the_listener_fails(self, websocket):
        ws = websocket.WebSocketApp.return_value
        ws.run_forever.side_effect = RuntimeError('boom')
        relay = RelayListener('wss://oauth.example.com', 'the-state', Mock())

        self.assertRaises(RuntimeError, relay.run)

        ws.close.assert_called_once_with()

    def test_an_error_is_logged_without_its_content(self, websocket):
        relay = RelayListener('wss://oauth.example.com', 'the-state', Mock())
        relay.run()
        on_error = websocket.WebSocketApp.call_args.kwargs['on_error']

        with self.assertLogs(
            'wazo_auth.plugins.external_auth.salesforce', level='DEBUG'
        ) as logs:
            on_error(Mock(), ValueError(CODE))

        assert_that(logs.output[0], contains_string('ValueError'))
        assert_that(logs.output[0], not_(contains_string(CODE)))
