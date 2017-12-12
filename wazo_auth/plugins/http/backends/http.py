# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from wazo_auth import http


class Backends(http.ErrorCatchingResource):

    def __init__(self, config):
        self._config = config

    def get(self):
        return {'data': self._config['loaded_plugins']}
