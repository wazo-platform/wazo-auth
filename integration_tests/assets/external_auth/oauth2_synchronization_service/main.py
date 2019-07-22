# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
import time

from flask import Flask, jsonify, request
from flask_sockets import Sockets

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
sockets = Sockets(app)

active_ws = {}


@sockets.route('/ws/<state>')
def websocket_event(ws, state):
    active_ws[state] = ws
    logger.info('WS connection waiting for %s', state)

    while not ws.closed:
        time.sleep(0.1)


@app.route('/<service>/authorize/<state>')
def authorize(service, state):
    body = dict(request.args)
    body['code'] = 'a-code'
    logger.info('Authorizing %s', state)
    ws = active_ws.get(state)
    if not ws:
        return '', 404
    ws.send(json.dumps(body))
    return '', 204


@app.route('/<service>/token', methods=['GET', 'POST'])
def get_microsoft_token(service):
    body = {
        'access_token': 'access_token',
        'expires_in': 42,
        'refresh_token': 'refresh_token',
        'scope': 'scope',
    }
    return jsonify(body), 200
