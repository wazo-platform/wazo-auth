# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import print_function

import json
import time

from flask import Flask, request
from flask_sockets import Sockets


app = Flask(__name__)
sockets = Sockets(app)

active_ws = {}


@sockets.route('/ws/<state>')
def websocket_event(ws, state):
    print('Waiting for activation')
    active_ws[state] = ws

    while not ws.closed:
        time.sleep(0.1)

    print('Activation complete')


@app.route('/<service>/authorize/<state>')
def authorize(service, state):
    body = dict(request.args)
    ws = active_ws.pop(state)
    print('received authorization for', state)
    ws.send(json.dumps(body))
    return '', 204
