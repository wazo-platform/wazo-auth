# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from flask import current_app
from wazo_auth import http


class Backends(http.ErrorCatchingResource):

    def get(self):
        return {'data': current_app.config['loaded_plugins']}
