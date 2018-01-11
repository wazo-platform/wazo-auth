# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from flask import request
from wazo_auth import http

logger = logging.getLogger(__name__)


class PasswordReset(http.ErrorCatchingResource):

    def get(self):
        logger.debug('Reset password for %s', request.args)
        return '', 204
